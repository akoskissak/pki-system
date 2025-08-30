package com.ftn.bsep.pki.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "pki.store")
public class KeyStoreConfig {
    private String caDir = "data/pki/keystores";
    private String eeDir = "data/pki/end-entities";
    private String eeJksPassword = "changeit";

    public String getCaDir() { return caDir; }
    public void setCaDir(String caDir) { this.caDir = caDir; }
    public String getEeDir() { return eeDir; }
    public void setEeDir(String eeDir) { this.eeDir = eeDir; }
    public String getEeJksPassword() { return eeJksPassword; }
    public void setEeJksPassword(String eeJksPassword) { this.eeJksPassword = eeJksPassword; }
}
