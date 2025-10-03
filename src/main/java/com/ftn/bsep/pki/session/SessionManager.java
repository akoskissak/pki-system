package com.ftn.bsep.pki.session;

import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Component
public class SessionManager {
    private final Map<String, SessionInfo> sessions = new ConcurrentHashMap<>();
    
    public void addSession(SessionInfo session){
        sessions.put(session.getTokenId(), session);
    }
    
    public List<SessionInfo> getUserSessions(String email, String currentTokenId) {
        return sessions.values().stream()
                .filter(sessionInfo -> sessionInfo.getEmail().equals(email))
                .map(sessionInfo -> {
                    sessionInfo.setCurrentSession(sessionInfo.getTokenId().equals(currentTokenId));
                    return sessionInfo;
                })
                .sorted((s1, s2) -> Boolean.compare(s2.getCurrentSession(), s1.getCurrentSession()))
                .collect(Collectors.toList());
    }
    
    public void removeSession(String tokenId) {
        sessions.remove(tokenId);
    }
    
    public void updateLastActivity(String tokenId) {
        SessionInfo sessionInfo = sessions.get(tokenId);
        if(sessionInfo != null) {
            sessionInfo.setLastActivity(LocalDateTime.now());
        }
    }
    
    public Map<String, SessionInfo> getSessions() {
        return sessions;
    }
}
