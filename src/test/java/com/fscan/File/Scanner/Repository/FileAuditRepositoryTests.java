package com.fscan.File.Scanner.Repository;

import com.fscan.File.Scanner.entity.FileAudit;
import com.fscan.File.Scanner.repository.FileAuditRepo;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.jdbc.EmbeddedDatabaseConnection;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;

import java.time.LocalDateTime;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

@DataJpaTest
@AutoConfigureTestDatabase(connection = EmbeddedDatabaseConnection.H2)
public class FileAuditRepositoryTests {

    @Autowired
    FileAuditRepo fileAuditRepo;

    @AfterEach
    void tearDown(){
        fileAuditRepo.deleteAll();
    }
    @Test
    public void FileAuditRepository_Save_ReturnSavedRecord(){

        FileAudit fileAudit = FileAudit.builder()
                .fileName("Sample.txt")
                .SHA256("")
                .analysisId("")
                .status("Testing Sample")
                .scanResults("")
                .last_status_time(LocalDateTime.now()).build();

        FileAudit savedFileRecord = fileAuditRepo.save(fileAudit);

        Assertions.assertThat(savedFileRecord).isNotNull();
        Assertions.assertThat(savedFileRecord.getId()).isGreaterThan(0);

    }

    @Test
    public void FileAuditRepository_SaveDuplicates_ShouldHaveDifferentId(){

        FileAudit fileAudit1 = FileAudit.builder()
                .fileName("Sample.txt")
                .SHA256("")
                .analysisId("")
                .status("Testing Sample")
                .scanResults("")
                .last_status_time(LocalDateTime.now()).build();

        FileAudit fileAudit2 = FileAudit.builder()
                .fileName("Sample.txt")
                .SHA256("")
                .analysisId("")
                .status("Testing Sample")
                .scanResults("")
                .last_status_time(LocalDateTime.now()).build();

        FileAudit savedFileRecord1 = fileAuditRepo.save(fileAudit1);
        FileAudit savedFileRecord2 = fileAuditRepo.save(fileAudit2);

        Assertions.assertThat(savedFileRecord1).isNotNull();
        Assertions.assertThat(savedFileRecord2).isNotNull();
        Assertions.assertThat(savedFileRecord1.getId()).isNotEqualTo(savedFileRecord2.getId());
        Assertions.assertThat(savedFileRecord1.getFileName()).isEqualTo(savedFileRecord2.getFileName());


    }

    @Test
    public void FileAuditRepository_findByAnalysisId_ShouldReturnNullForUnknownAnalysisID(){

        FileAudit fileAudit1 = FileAudit.builder()
                .fileName("Sample.txt")
                .SHA256("")
                .analysisId("1234567")
                .status("Testing Sample")
                .scanResults("")
                .last_status_time(LocalDateTime.now()).build();

        FileAudit fileAudit2 = FileAudit.builder()
                .fileName("Sample.txt")
                .SHA256("")
                .analysisId("1234568")
                .status("Testing Sample")
                .scanResults("")
                .last_status_time(LocalDateTime.now()).build();

        FileAudit fileAudit3 = FileAudit.builder()
                .fileName("Sample.txt")
                .SHA256("")
                .analysisId("1234569")
                .status("Testing Sample")
                .scanResults("")
                .last_status_time(LocalDateTime.now()).build();

        fileAuditRepo.save(fileAudit1);
        fileAuditRepo.save(fileAudit2);
        fileAuditRepo.save(fileAudit3);

        List<FileAudit> recordRetrievedByQuery1 = fileAuditRepo.findByanalysisId("1234566");
        assertTrue(recordRetrievedByQuery1.isEmpty(), "Expected an empty list but got a non-empty list");

    }

    @Test
    public void FileAuditRepository_FindByAnalysisId_ShouldReturnSearchedRecord(){

        FileAudit fileAudit1 = FileAudit.builder()
                .fileName("Sample.txt")
                .SHA256("")
                .analysisId("1234567")
                .status("Testing Sample")
                .scanResults("")
                .last_status_time(LocalDateTime.now()).build();

        FileAudit fileAudit2 = FileAudit.builder()
                .fileName("Sample.txt")
                .SHA256("")
                .analysisId("1234568")
                .status("Testing Sample")
                .scanResults("")
                .last_status_time(LocalDateTime.now()).build();

        FileAudit fileAudit3 = FileAudit.builder()
                .fileName("Sample.txt")
                .SHA256("")
                .analysisId("1234569")
                .status("Testing Sample")
                .scanResults("")
                .last_status_time(LocalDateTime.now()).build();

        fileAuditRepo.save(fileAudit1);
        fileAuditRepo.save(fileAudit2);
        fileAuditRepo.save(fileAudit3);

        List<FileAudit> recordRetrievedByQuery2 = fileAuditRepo.findByanalysisId("1234567");
        Assertions.assertThat(recordRetrievedByQuery2).isNotNull();
        Assertions.assertThat(recordRetrievedByQuery2.get(0).getId()).isEqualTo(fileAudit1.getId());
    }
}