package com.example;

import groovy.lang.GroovyClassLoader;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Arrays;

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
    if (this.groovyScript != null && !this.groovyScript.trim().isEmpty())
      processGroovyScript(); 
  }
  
  private void processGroovyScript() {
    GroovyClassLoader groovyClassLoader = null;
    try {
      groovyClassLoader = new GroovyClassLoader(Thread.currentThread().getContextClassLoader());
      Class<?> groovyClass = groovyClassLoader.parseClass(this.groovyScript);
      System.out.println("Groovy class parsed successfully: " + groovyClass.getName());
      System.out.println("Class modifiers: " + Modifier.toString(groovyClass.getModifiers()));
      System.out.println("Available methods:");
      for (Method method : groovyClass.getDeclaredMethods())
        System.out.println("  - " + method.getName() + "(" + 
            Arrays.toString((Object[])method.getParameterTypes()) + ")"); 
    } catch (Exception e) {
      System.err.println("Error parsing Groovy script: " + e.getMessage());
      e.printStackTrace();
    } finally {
      if (groovyClassLoader != null)
        try {
          groovyClassLoader.close();
        } catch (IOException e) {
          System.err.println("Error closing GroovyClassLoader: " + e.getMessage());
        }  
    } 
  }
  
  public String toString() {
    return "Testing{name='" + this.name + "', price=" + this.price + ", hasGroovyScript=" + ((this.groovyScript != null) ? 1 : 0) + "}";
  }
}
