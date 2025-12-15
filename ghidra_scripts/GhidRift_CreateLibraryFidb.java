//Create FunctionID database from all programs in current project
//Based on CreateMultipleLibraries.java but simplified for single library
//@author GhidRift
//@category FunctionID
//@keybinding
//@menupath
//@toolbar

import java.io.*;
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.feature.fid.db.*;
import ghidra.feature.fid.service.*;
import ghidra.framework.model.*;
import ghidra.program.model.listing.*;
import ghidra.util.task.TaskMonitor;

public class GhidRift_CreateLibraryFidb extends GhidraScript {

    @Override
    protected void run() throws Exception {
        // Get script arguments
        // Expected: fidDbPath, libraryFamily, libraryVersion, libraryVariant
        if (getScriptArgs().length < 4) {
            printerr("Usage: GhidRift_CreateLibraryFidb <fidb_path> <library_family> <library_version> <library_variant>");
            return;
        }
        
        String fidDbPath = getScriptArgs()[0];
        String libraryFamily = getScriptArgs()[1];
        String libraryVersion = getScriptArgs()[2];
        String libraryVariant = getScriptArgs()[3];
        
        println("Creating FunctionID database from project:");
        println("  Output: " + fidDbPath);
        println("  Family: " + libraryFamily);
        println("  Version: " + libraryVersion);
        println("  Variant: " + libraryVariant);
        
        // Get all programs in the current project
        Project project = getState().getProject();
        ProjectData projectData = project.getProjectData();
        DomainFolder rootFolder = projectData.getRootFolder();
        
        ArrayList<DomainFile> programs = new ArrayList<>();
        findPrograms(programs, rootFolder);
        
        if (programs.isEmpty()) {
            printerr("No programs found in project!");
            return;
        }
        
        println("Found " + programs.size() + " programs to process");
        
        // Create the FID database
        File fidFile = new File(fidDbPath);
        
        // Remove existing file if it exists
        if (fidFile.exists()) {
            fidFile.delete();
        }
        
        // Create new FID database file
        FidFileManager fidFileManager = FidFileManager.getInstance();
        fidFileManager.createNewFidDatabase(fidFile);
        
        // Add the file to the manager so we can get a FidFile object
        fidFileManager.addUserFidFile(fidFile);
        
        // Get FidFile object from user added files
        FidFile fidFileObj = null;
        List<FidFile> userFiles = fidFileManager.getUserAddedFiles();
        for (FidFile userFile : userFiles) {
            if (userFile.getPath().equals(fidFile.getAbsolutePath())) {
                fidFileObj = userFile;
                break;
            }
        }
        
        if (fidFileObj == null) {
            printerr("Failed to get FidFile object for: " + fidDbPath);
            return;
        }
        
        // Open the database for writing
        FidDB fidDb = fidFileObj.getFidDB(true);
        
        try {
            // Create FID service
            FidService service = new FidService();
            
            // Get language from first program
            String languageID = null;
            if (!programs.isEmpty()) {
                try {
                    DomainObject obj = programs.get(0).getDomainObject(this, false, false, TaskMonitor.DUMMY);
                    if (obj instanceof Program) {
                        languageID = ((Program) obj).getLanguageID().toString();
                    }
                    obj.release(this);
                } catch (Exception e) {
                    println("Warning: Could not get language from first program: " + e.getMessage());
                }
            }
            
            // Create library from all programs
            println("Creating library from " + programs.size() + " programs...");
            
            FidPopulateResult result = service.createNewLibraryFromPrograms(
                fidDb,
                libraryFamily,
                libraryVersion, 
                libraryVariant,
                programs,
                null,  // translatorName
                languageID != null ? new ghidra.program.model.lang.LanguageID(languageID) : null,
                null,  // taskMonitor - use null, we'll provide monitor
                null,  // commonSymbols
                monitor // Use script monitor
            );
            
            // Report results
            if (result != null) {
                println("Library created successfully!");
                println("  Total functions attempted: " + result.getTotalAttempted());
                println("  Total functions added: " + result.getTotalAdded());
                println("  Total functions excluded: " + result.getTotalExcluded());
                
                // Show exclusion breakdown
                if (result.getTotalExcluded() > 0) {
                    println("  Exclusion breakdown:");
                    for (Map.Entry<FidPopulateResult.Disposition, Integer> entry : result.getFailures().entrySet()) {
                        if (entry.getKey() != FidPopulateResult.Disposition.INCLUDED) {
                            println("    " + entry.getKey() + ": " + entry.getValue());
                        }
                    }
                }
            } else {
                printerr("Failed to create library - result was null");
                return;
            }
            
            // Save the database
            fidDb.saveDatabase("Saving FID database", monitor);
            println("FID database saved successfully to: " + fidDbPath);
            
        } catch (Exception e) {
            printerr("Error creating FID database: " + e.getMessage());
            e.printStackTrace();
            throw e;
        } finally {
            fidDb.close();
        }
    }
    
    /**
     * Recursively finds all domain objects that are program files under a domain folder.
     * @param programs the "return" value; found programs are placed in this collection
     * @param folder the domain folder to search
     */
    private void findPrograms(ArrayList<DomainFile> programs, DomainFolder folder) {
        if (folder == null) {
            return;
        }
        
        // Get all files in this folder
        DomainFile[] files = folder.getFiles();
        for (DomainFile file : files) {
            // Check if it's a program using content type
            if (file.getContentType().equals("Program")) {
                programs.add(file);
            }
        }
        
        // Recurse into subfolders
        DomainFolder[] subfolders = folder.getFolders();
        for (DomainFolder subfolder : subfolders) {
            findPrograms(programs, subfolder);
        }
    }
}