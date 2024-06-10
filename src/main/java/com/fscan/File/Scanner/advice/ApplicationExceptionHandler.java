package com.fscan.File.Scanner.advice;


import com.fscan.File.Scanner.exception.AnalysisIdNotFoundException;
import com.fscan.File.Scanner.exception.FileAccessException;
import com.fscan.File.Scanner.exception.ScanningUnderProgressException;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;


@RestControllerAdvice
public class ApplicationExceptionHandler {

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(AnalysisIdNotFoundException.class)
    public String HandelInvalidAnalysisId(AnalysisIdNotFoundException ex){

        return " Please enter a valid `Analysis Id` ";

    }

    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    @ExceptionHandler(FileAccessException.class)
    public String Handel(FileAccessException ex){

    //        byte[] getBytes()
    //         throws java.io.IOException
    //Return the contents of the file as an array of bytes.
    //Returns:
    //the contents of the file as bytes, or an empty byte array if empty
    //Throws:
    //java.io.IOException - in case of access errors (if the temporary store fails)

        return "Unable to Read the contents of MultipartFile";
    }

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(ScanningUnderProgressException.class)
    public String HandelScanningUnderProgress(ScanningUnderProgressException ex){
        return "File is being scanned at VirusTotal,Please try again after some time";
    }

}
