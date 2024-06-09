package com.fscan.File.Scanner.entity;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder

@Entity
@Table(name = "file_logs")
public class FileAudit {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;

    @Column(name = "FileName",nullable = false)
    private String fileName;

    @Column(name = "AID",nullable = true)
    private String analysisId;

    @Column(name = "Status",nullable = false)
    private String status;

    @Column(name = "ScanResults",nullable = true)
    private String scanResults;

    @Column(name = "LastStatusTime",nullable = false)
    private LocalDateTime last_status_time;

    @Column(name = "SHA256",nullable = true)
    private String SHA256;

}
