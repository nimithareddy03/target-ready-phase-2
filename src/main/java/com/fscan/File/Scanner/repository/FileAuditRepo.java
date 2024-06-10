package com.fscan.File.Scanner.repository;

import com.fscan.File.Scanner.entity.FileAudit;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;

import java.util.List;

@RepositoryRestResource
public interface FileAuditRepo extends JpaRepository<FileAudit,Long> {

    List<FileAudit> findByanalysisId(String analysisId);

    List<FileAudit> findBySHA256(String SHA256);

}
