<%@ page language="java" contentType="text/plain; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="java.util.*" %>
<%@ page import="java.io.*" %>
<%
    // Retrieve training data from the records
    String url = request.getParameter("url");
    
    if (url == null || url.trim().isEmpty()) {
        out.println("No URL provided for training data retrieval.");
        return;
    }
    
    List<Map<String, String>> history = (List<Map<String, String>>) session.getAttribute("trainingHistory");
    
    if (history != null) {
        // Find the training data in the records
        for (Map<String, String> item : history) {
            if (url.equals(item.get("url"))) {
                String content = item.get("content");
                
                if (content != null) {
                    // Return Base64 encoded content directly
                    out.println(content);
                    return;
                }
            }
        }
    }
    
    out.println("Training data not found in the records for this source.");
%> 