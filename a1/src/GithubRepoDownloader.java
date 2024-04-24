import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.api.errors.GitAPIException;
import java.util.ArrayList;
import java.util.List;
import java.io.File;
import java.io.IOException;
import java.nio.file.*;
import java.util.stream.Stream;

public class GithubRepoDownloader {
    
	public void cloneRepo(String repoUrl, String destination) {
        File file = new File(destination);
        if(file.exists() && file.isDirectory() && file.list().length > 0){
            System.out.println(destination + " already exists and is not empty.");
            return;
        }

        try {
            System.out.println("Cloning " + repoUrl + " into " + destination);
            Git.cloneRepository()
                    .setURI(repoUrl)
                    .setDirectory(new File(destination))
                    .call();
            System.out.println("Completed cloning");
        } catch (GitAPIException e) {
            System.out.println("There was an error cloning the repository");
            e.printStackTrace();
        }
    }

    public boolean isAndroidRepo(String repoPath) {
        // Checks if a repository is an Android repository
        // by looking for a 'build.gradle' or 'AndroidManifest.xml' file
        Path start = Paths.get(repoPath);
        String glob = "glob:**/{build.gradle,AndroidManifest.xml}";
        try (Stream<Path> stream = Files.find(start, Integer.MAX_VALUE,
                (path, attr) -> FileSystems.getDefault().getPathMatcher(glob).matches(path))) {
            return stream.findAny().isPresent();
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
    }
    
    public List<Path> getAllJavaFiles(String directory) {
        List<Path> javaFiles = new ArrayList<>();
        Path start = Paths.get(directory);
        String pattern = "\"**/*.java\";";

        try (Stream<Path> stream = Files.find(start, Integer.MAX_VALUE,
                (path, attr) -> path.getFileName().toString().endsWith(".java"))) {
            stream.forEach(javaFiles::add);
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.out.println("*********************************");
        System.out.println("Number of Java files: " + javaFiles.size());
        System.out.println("*********************************");
        return javaFiles;
    }

    
    public void extractRepo(String repoUrl, String destination) {
        File file = new File(destination);
        if(file.exists() && file.isDirectory() && file.list().length > 0) {
            System.out.println(destination + " already exists and is not empty. Checking if it's an Android repository");
        } else {
            cloneRepo(repoUrl, destination);
        }

        if (isAndroidRepo(destination)) {
            System.out.println("This is an Android repository");
        } else {
            System.out.println("This is not an Android repository");
        }
    }

    public static void main(String[] args) {
        GithubRepoDownloader downloader = new GithubRepoDownloader();
        // Replace these values with the actual repo URL and destination directory
        String repoUrl = "https://github.com/avjinder/Minimal-Todo.git";
        //String destination = "/path/to/clone/directory";
        String destination = "/Users/chandra/Desktop/clonedRepos";

        downloader.extractRepo(repoUrl, destination);
        System.out.println("Getting all java files from destination");
        List<Path> javaFiles = downloader.getAllJavaFiles(destination);
        System.out.println("Java files in " + repoUrl + "\n");
        javaFiles.forEach(path -> {
            String fileName = path.getFileName().toString();
            System.out.println(fileName);
        });

    }
}