package com.Spring_Security_JWT.configuration;

import java.io.IOException;
import java.util.Collections;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

	@Component
	public class LoggingFilter extends OncePerRequestFilter {

	    private static final Logger logger = LoggerFactory.getLogger(LoggingFilter.class);

	    @Override
	    protected void doFilterInternal(HttpServletRequest request,
	                                    HttpServletResponse response,
	                                    FilterChain filterChain)
	            throws ServletException, IOException {

	        long startTime = System.currentTimeMillis();

	        //  Log Request Details
	        logger.info("➡️ Incoming Request: {} {}", request.getMethod(), request.getRequestURI());

	        // Optional: Log Headers
	        Collections.list(request.getHeaderNames())
	                .forEach(header -> logger.debug("Header: {} = {}", header, request.getHeader(header)));

	        try {
	            //  Continue Filter Chain
	            filterChain.doFilter(request, response);
	        } finally {
	            long duration = System.currentTimeMillis() - startTime;

	            //  Log Response Details
	            logger.info("⬅️ Response: {} {} | Status: {} | Time: {} ms",
	                    request.getMethod(),
	                    request.getRequestURI(),
	                    response.getStatus(),
	                    duration);
	        }
	    }
	}


