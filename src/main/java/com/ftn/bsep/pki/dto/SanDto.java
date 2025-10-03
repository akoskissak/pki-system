package com.ftn.bsep.pki.dto;

public class SanDto {
    private String type; // "DNS", "IP", "EMAIL", "URI"
    private String value;

    public String getType() { return type; }
    public void setType(String type) { this.type = type; }
    public String getValue() { return value; }
    public void setValue(String value) { this.value = value; }

    public SanDto(String type, String value) {
        this.type = type;
        this.value = value;
    }
}
