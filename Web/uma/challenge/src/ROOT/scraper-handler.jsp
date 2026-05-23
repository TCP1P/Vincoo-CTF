<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="java.util.*" %>
<%@ page import="java.text.SimpleDateFormat" %>
<%@ page import="java.net.URL" %>
<%@ page import="java.io.*" %>
<%@ page import="java.util.Base64" %>
<%
    // Handle shadow weaving processing
    if ("POST".equals(request.getMethod())) {
        // Get form parameters
        String websiteUrl = request.getParameter("websiteUrl");
        String scrapingType = request.getParameter("scrapingType");
        String includeImages = request.getParameter("includeImages");
        String includeLinks = request.getParameter("includeLinks");
        
        // Validate realm path
        if (websiteUrl != null && !websiteUrl.trim().isEmpty()) {
            try {
                // Update shadow weaver preferences in session
                Map<String, String> userPrefs = (Map<String, String>) session.getAttribute("userPreferences");
                if (userPrefs == null) {
                    userPrefs = new HashMap<>();
                }
                userPrefs.put("scrapingType", scrapingType);
                userPrefs.put("includeImages", includeImages);
                userPrefs.put("includeLinks", includeLinks);
                session.setAttribute("userPreferences", userPrefs);
                
                // Weave the shadow from the digital realm
                String scrapedContent = weaveShadow(websiteUrl, scrapingType, includeImages, includeLinks);
                String timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
                String size = String.valueOf(scrapedContent.length()) + " characters";
                String preview = generateShadowPreview(scrapedContent, scrapingType);
                
                // Create shadow weaving data
                Map<String, String> scrapingData = new HashMap<>();
                scrapingData.put("url", websiteUrl);
                scrapingData.put("scrapingType", scrapingType);
                scrapingData.put("includeImages", includeImages);
                scrapingData.put("includeLinks", includeLinks);
                scrapingData.put("content", scrapedContent);
                scrapingData.put("preview", preview);
                scrapingData.put("timestamp", timestamp);
                scrapingData.put("size", size);
                scrapingData.put("sessionId", session.getId());
                
                // Add to training records
                List<Map<String, String>> history = (List<Map<String, String>>) session.getAttribute("trainingHistory");
                if (history == null) {
                    history = new ArrayList<>();
                }
                
                // Add to beginning of scrolls (most recent first)
                history.add(0, scrapingData);
                
                // Keep only last 20 scrolls
                if (history.size() > 20) {
                    history = history.subList(0, 20);
                }
                
                session.setAttribute("trainingHistory", history);
                
                // Redirect back to sanctuary with success message
                response.sendRedirect("index.jsp?success=content_scraped&url=" + 
                                    java.net.URLEncoder.encode(websiteUrl, "UTF-8"));
                return;
                
            } catch (Exception e) {
                // Handle shadow barrier errors
                response.sendRedirect("index.jsp?error=connection_error&url=" + 
                                    java.net.URLEncoder.encode(websiteUrl, "UTF-8"));
                return;
            }
        } else {
            response.sendRedirect("index.jsp?error=invalid_url");
            return;
        }
    }
%>

<%!
    private String weaveShadow(String url, String scrapingType, String includeImages, String includeLinks) throws IOException {
        try {
            URL websiteUrl = new URL(url);
            java.net.URLConnection connection = websiteUrl.openConnection();
            
            // Read all content as pure bytes
            java.io.InputStream inputStream = connection.getInputStream();
            java.io.ByteArrayOutputStream buffer = new java.io.ByteArrayOutputStream();
            int nRead;
            byte[] data = new byte[16384];
            while ((nRead = inputStream.read(data, 0, data.length)) != -1) {
                buffer.write(data, 0, nRead);
            }
            inputStream.close();
            
            // Base64 encode the raw bytes
            return java.util.Base64.getEncoder().encodeToString(buffer.toByteArray());
            
        } catch (IOException e) {
            throw new IOException("Unable to breach the shadow barrier of " + url + ": " + e.getMessage());
        }
    }
    
    private String generateShadowPreview(String content, String scrapingType) {
        try {
            // Decode Base64 content for preview generation
            byte[] decodedBytes = java.util.Base64.getDecoder().decode(content);
            String decodedContent = new String(decodedBytes, "UTF-8");
            
            String preview = decodedContent;
            
            // Remove shadow script tags for preview
            if ("html".equals(scrapingType)) {
                preview = preview.replaceAll("<[^>]*>", " ");
                preview = preview.replaceAll("\\s+", " ");
            }
            
            // Limit preview length for mortal eyes
            if (preview.length() > 200) {
                preview = preview.substring(0, 200) + "...";
            }
            
            return preview.trim();
        } catch (Exception e) {
            // If decoding fails or content is binary, return a generic preview
            return "[Binary content - " + content.length() + " characters]";
        }
    }
%>

<!DOCTYPE html>
<html>
<head>
    <title>Processing Scraper...</title>
    <meta http-equiv="refresh" content="0;url=index.jsp">
</head>
<body>
    <p>Processing scraper...</p>
</body>
</html> 