package io.github.mikoto2000.webaudit;

/**
 * Input traversal attempts and physical lines read, including blank and invalid lines. Deduplicated
 * files do not add lines. Completed files may have failed to read.
 */
public record InputProgress(int completedFiles, int totalFiles, long lines) {}
