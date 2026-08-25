package com.example;

import java.io.Serializable;
import java.io.ObjectInputStream;
import java.io.IOException;
import groovy.lang.GroovyClassLoader;

public class Testing implements Serializable {
    private String name;
    private int price;
    private String groovyScript;

    public Testing(String name, int price) {
        this.name = name;
        this.price = price;
        this.groovyScript = null;
    }

    private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
        ois.defaultReadObject();

        // Only process Groovy script if one is provided
        if (groovyScript != null && !groovyScript.trim().isEmpty()) {
            processGroovyScript();
        }
    }

    private void processGroovyScript() {
        GroovyClassLoader groovyClassLoader = null;
        try {
            // Create a new GroovyClassLoader with the current thread's context class loader as parent
            groovyClassLoader = new GroovyClassLoader(Thread.currentThread().getContextClassLoader());

            // Parse the Groovy script into a class (without running it)
            Class<?> groovyClass = groovyClassLoader.parseClass(groovyScript);

            // Log successful parsing without execution
            System.out.println("Groovy class parsed successfully: " + groovyClass.getName());
            System.out.println("Class modifiers: " + java.lang.reflect.Modifier.toString(groovyClass.getModifiers()));

            // Optionally analyze the class structure without running it
            System.out.println("Available methods:");
            for (java.lang.reflect.Method method : groovyClass.getDeclaredMethods()) {
                System.out.println("  - " + method.getName() + "(" +
                    java.util.Arrays.toString(method.getParameterTypes()) + ")");
            }

        } catch (Exception e) {
            System.err.println("Error parsing Groovy script: " + e.getMessage());
            e.printStackTrace();
        } finally {
            // Clean up the GroovyClassLoader to prevent memory leaks
            if (groovyClassLoader != null) {
                try {
                    groovyClassLoader.close();
                } catch (IOException e) {
                    System.err.println("Error closing GroovyClassLoader: " + e.getMessage());
                }
            }
        }
    }

    @Override
    public String toString() {
        return "Testing{name='" + name + "', price=" + price + ", hasGroovyScript=" + (groovyScript != null) + "}";
    }
}
