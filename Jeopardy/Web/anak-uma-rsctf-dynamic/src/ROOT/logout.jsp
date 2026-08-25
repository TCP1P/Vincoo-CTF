<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%
    // Vanish into the shadows - invalidate session
    session.invalidate();

    // Redirect to home page
    response.sendRedirect("index.jsp?success=logged_out");
%>