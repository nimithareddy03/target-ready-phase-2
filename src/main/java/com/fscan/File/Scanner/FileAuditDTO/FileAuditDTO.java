package com.fscan.File.Scanner.FileAuditDTO;


import lombok.Getter;
import lombok.Setter;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

@Getter
@Setter

@Component
public class FileAuditDTO {

    private Long id;
    private String fileName;
    private String status;
    private String SHA256;
    private String analysisId;
    private String scanResults;
    private LocalDateTime last_updated_status;

}
