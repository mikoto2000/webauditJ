package io.github.mikoto2000.webaudit;
import java.io.*;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
final class ManagedFiles {
    private ManagedFiles() {}
    static void directories(Path path)throws IOException{if(FileSystems.getDefault().supportedFileAttributeViews().contains("posix"))Files.createDirectories(path,PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));else Files.createDirectories(path);}
    static Path createFile(Path path)throws IOException{if(FileSystems.getDefault().supportedFileAttributeViews().contains("posix"))return Files.createFile(path,PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));return Files.createFile(path);}
    static void deleteTree(Path root,Path target)throws IOException{
        Path absolute=root.toAbsolutePath().normalize(),candidate=target.toAbsolutePath().normalize();if(candidate.equals(absolute)||!candidate.startsWith(absolute))throw new IOException("cleanup path outside GeoIP directory");
        if(!Files.exists(candidate,LinkOption.NOFOLLOW_LINKS))return;
        Files.walkFileTree(candidate,new SimpleFileVisitor<>(){public FileVisitResult visitFile(Path file,java.nio.file.attribute.BasicFileAttributes attributes)throws IOException{Files.delete(file);return FileVisitResult.CONTINUE;}public FileVisitResult postVisitDirectory(Path directory,IOException error)throws IOException{if(error!=null)throw error;Files.delete(directory);return FileVisitResult.CONTINUE;}});
    }
}
