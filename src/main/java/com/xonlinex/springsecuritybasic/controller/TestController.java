package com.xonlinex.springsecuritybasic.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@RestController
public class TestController {

    @Autowired
    private SessionRegistry sessionRegistry;

    @GetMapping("/test")
    public String test() {
        return "<h1>login</h1>";
    }

    @GetMapping("/home")
    public String test2() {
        return "<h1>home</h1>";
    }

    //  detalles sobre las sesiones activas en tu aplicación en json
    @GetMapping("/sessions")
    public ResponseEntity<?> session() {
        String sessionId = "";
        User user = null;
        List<Object> sessions = sessionRegistry.getAllPrincipals();
        for (Object session : sessions){
            if(session instanceof User){
                user = (User) session;
            }
            List<SessionInformation> sessionInformations = sessionRegistry.getAllSessions(session, false);
            for (SessionInformation sessionInformation : sessionInformations){
                sessionId = sessionInformation.getSessionId();
            }
        }
        Map<String, Object> response = new HashMap<>();
        response.put("response", "hello world");
        response.put("sessionId", sessionId);
        response.put("User", user);
        return ResponseEntity.ok(response);
    }

}
