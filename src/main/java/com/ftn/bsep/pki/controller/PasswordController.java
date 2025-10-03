package com.ftn.bsep.pki.controller;

import com.ftn.bsep.pki.dto.*;
import com.ftn.bsep.pki.entity.Password;
import com.ftn.bsep.pki.entity.User;
import com.ftn.bsep.pki.repository.IUserRepository;
import com.ftn.bsep.pki.service.PasswordService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/passwords")
public class PasswordController {
    private final PasswordService passwordService;
    private final IUserRepository userRepository;
    private static final Logger logger = LoggerFactory.getLogger(PasswordController.class);

    public PasswordController(PasswordService passwordService, IUserRepository userRepository) {
        this.passwordService = passwordService;
        this.userRepository = userRepository;
    }

    private Optional<User> getLoggedInUser(Principal principal) {
        return userRepository.findByEmail(principal.getName());
    }

    @PostMapping
    @PreAuthorize("hasAuthority('END_USER')")
    public ResponseEntity<Password> savePassword(@RequestBody PasswordDto passwordDto, Principal principal) {
        User owner = getLoggedInUser(principal).orElseThrow(() -> new RuntimeException("User not found"));

        Password savedPassword = passwordService.savePassword(
                passwordDto.getSiteName(),
                passwordDto.getUsername(),
                passwordDto.getEncryptedPassword(),
                owner
        );
        return ResponseEntity.ok(savedPassword);
    }

    @GetMapping
    @PreAuthorize("hasAuthority('END_USER')")
    public ResponseEntity<List<PasswordDtoResponse>> getMyPasswords(Principal principal) {
        User user = getLoggedInUser(principal).orElseThrow(() -> new RuntimeException("User not found"));

        logger.info("User id={} ({}) requested their password list", user.getId(), user.getEmail());

        List<Password> passwords = passwordService.getPasswordsForUser(user.getId());
        List<PasswordDtoResponse> dtoList = passwords.stream()
                .map(password -> {
                    PasswordDtoResponse dto = new PasswordDtoResponse();
                    dto.setId(password.getId());
                    dto.setSiteName(password.getSiteName());
                    dto.setUsername(password.getUsername());
                    dto.setOwnerId(password.getOwner().getId());
                    dto.setCreatedAt(password.getCreatedAt());

                    List<SharedPasswordDtoResponse> sharesDto = password.getShares().stream()
                            .map(share -> {
                                SharedPasswordDtoResponse shareDto = new SharedPasswordDtoResponse();
                                shareDto.setTargetUserId(share.getUserId());
                                shareDto.setEncryptedPasswordForTargetUser(share.getEncryptedPassword());
                                shareDto.setSharedAt(share.getSharedAt());
                                shareDto.setOwnerId(share.getSharedByUserId());
                                shareDto.setTargetUserEmail(userRepository.findById(share.getUserId()).get().getEmail());
                                logger.debug("Shared password id={} shared with userId={} at {}",
                                        password.getId(), share.getUserId(), share.getSharedAt());

                                return shareDto;
                            }).collect(Collectors.toList());
                    dto.setShares(sharesDto);
                    return dto;
                }).collect(Collectors.toList());
        
        logger.info("Returning {} passwords for user id={}", dtoList.size(), user.getId());
        return ResponseEntity.ok(dtoList);
    }

    @PostMapping("/{passwordId}/share")
    @PreAuthorize("hasAuthority('END_USER')")
    public ResponseEntity<Void> sharePassword(
            @PathVariable Long passwordId,
            @RequestBody SharePasswordDto shareDto,
            Principal principal) {

        User owner = getLoggedInUser(principal).orElseThrow(() -> new RuntimeException("User not found"));

        passwordService.sharePassword(passwordId, owner.getId(), shareDto.getTargetUserId(), shareDto.getEncryptedPasswordForTargetUser());

        return ResponseEntity.ok().build();
    }

    @GetMapping("/shared-with-me")
    @PreAuthorize("hasAuthority('END_USER')")
    public ResponseEntity<List<SharedWithMePasswordDto>> getSharedWithMe(Principal principal) {
        User currentUser = getLoggedInUser(principal)
                .orElseThrow(() -> new RuntimeException("User not found"));

        List<Password> sharedPasswords = passwordService.getPasswordsSharedWithUser(currentUser.getId());

        List<SharedWithMePasswordDto> dtoList = sharedPasswords.stream()
                .flatMap(password -> password.getShares().stream()
                        .filter(share -> Objects.equals(share.getUserId(), currentUser.getId()) && !Objects.equals(share.getSharedByUserId(), currentUser.getId()))
                        .map(share -> new SharedWithMePasswordDto(
                                password.getId(),
                                password.getSiteName(),
                                password.getUsername(),
                                String.valueOf(password.getOwner().getId()),
                                password.getOwner().getEmail(),
                                share.getSharedAt(),
                                share.getEncryptedPassword()
                        ))
                ).collect(Collectors.toList());

        return ResponseEntity.ok(dtoList);
    }

    @DeleteMapping("/{passwordId}")
    @PreAuthorize("hasAuthority('END_USER')")
    public ResponseEntity<Void> deletePassword(@PathVariable Long passwordId, Principal principal) {
        User currentUser = getLoggedInUser(principal)
                .orElseThrow(() -> new RuntimeException("User not found"));

        Password password = passwordService.getPasswordById(passwordId)
                .orElseThrow(() -> new RuntimeException("Password not found"));

        if (!Objects.equals(password.getOwner().getId(), currentUser.getId())) {
            return ResponseEntity.status(403).build();
        }

        passwordService.deletePassword(passwordId);
        return ResponseEntity.ok().build();
    }
}
