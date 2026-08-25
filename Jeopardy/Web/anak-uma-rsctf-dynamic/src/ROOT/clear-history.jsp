<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%
    // Clear all training records
    session.removeAttribute("trainingHistory");

    // Redirect back to index with success message
    response.sendRedirect("index.jsp?success=history_cleared");
%>