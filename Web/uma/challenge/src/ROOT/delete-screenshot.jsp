<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="java.util.*" %>
<%
    // Delete training data from the records
    String url = request.getParameter("url");
    
    if (url != null && !url.trim().isEmpty()) {
        List<Map<String, String>> history = (List<Map<String, String>>) session.getAttribute("trainingHistory");
        
        if (history != null) {
            // Remove the training data from the records
            history.removeIf(item -> url.equals(item.get("url")));
            session.setAttribute("trainingHistory", history);
        }
        
        response.sendRedirect("index.jsp?success=content_deleted&url=" + 
                            java.net.URLEncoder.encode(url, "UTF-8"));
    } else {
        response.sendRedirect("index.jsp?error=invalid_url");
    }
%> 