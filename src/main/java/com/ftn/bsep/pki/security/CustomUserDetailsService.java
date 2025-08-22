package com.ftn.bsep.pki.security;

import com.ftn.bsep.pki.repository.IUserRepository;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class CustomUserDetailsService implements UserDetailsService {
    private final IUserRepository userRepository;
    
    public CustomUserDetailsService(IUserRepository userRepository) {
        this.userRepository = userRepository;
    }
    
    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        return userRepository.findByEmail(email)
                .map(user -> {
                    SimpleGrantedAuthority authority = new SimpleGrantedAuthority(user.getRole().getName().name());

                    return new org.springframework.security.core.userdetails.User(
                            user.getEmail(),
                            user.getPassword(),
                            List.of(authority)
                    );
                })
                .orElseThrow(() -> new UsernameNotFoundException("User '" + email + "' not found"));
    }
}
