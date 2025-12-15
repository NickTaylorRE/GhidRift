//Extract Rust metadata from binaries
//@author GhidRift
//@category GhidRift
//@keybinding 
//@menupath Tools.GhidRift.Extract Metadata
//@toolbar 

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
// StringUtilities import removed - not needed

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
// Gson imports removed - using manual JSON generation for Docker compatibility

public class GhidRift_ExtractMetadata extends GhidraScript {
    
    // Regular expression patterns from RIFT
    private static final Pattern RE_COMMITHASH = Pattern.compile(".{0,250}rustc[\\\\|/]([0-9a-zA-Z]{40})[\\\\|/]");
    private static final Pattern RE_RUSTLIB = Pattern.compile(".{0,250}[\\\\|/](.{1,50}-\\d+\\.\\d+\\.\\d+(-.{1,20})?)[\\\\|/]src[\\\\|/].{1,100}\\.rs");
    
    // Environment detection strings
    private static final Map<String, String> ENV_STRINGS = new HashMap<>();
    static {
        ENV_STRINGS.put("Mingw-w64 runtime failure:", "gnu");
        ENV_STRINGS.put("_CxxThrowException", "msvc");
        ENV_STRINGS.put("std/src/sys/alloc/uefi.rs", "uefi");
    }
    
    // Metadata container class
    private static class RustMetadata {
        String commitHash;
        String targetTriple;
        String arch;
        String vendor = "unknown";
        String os;
        String env;
        List<String> crates = new ArrayList<>();
        
        public String toJson() {
            StringBuilder json = new StringBuilder();
            json.append("{\n");
            json.append("  \"commitHash\": ").append(jsonString(commitHash)).append(",\n");
            json.append("  \"targetTriple\": ").append(jsonString(targetTriple)).append(",\n");
            json.append("  \"arch\": ").append(jsonString(arch)).append(",\n");
            json.append("  \"vendor\": ").append(jsonString(vendor)).append(",\n");
            json.append("  \"os\": ").append(jsonString(os)).append(",\n");
            json.append("  \"env\": ").append(jsonString(env)).append(",\n");
            json.append("  \"crates\": [\n");
            
            for (int i = 0; i < crates.size(); i++) {
                json.append("    ").append(jsonString(crates.get(i)));
                if (i < crates.size() - 1) {
                    json.append(",");
                }
                json.append("\n");
            }
            
            json.append("  ]\n");
            json.append("}");
            return json.toString();
        }
        
        private String jsonString(String value) {
            if (value == null) {
                return "null";
            }
            // Escape JSON special characters
            String escaped = value.replace("\\", "\\\\")
                                 .replace("\"", "\\\"")
                                 .replace("\n", "\\n")
                                 .replace("\r", "\\r")
                                 .replace("\t", "\\t");
            return "\"" + escaped + "\"";
        }
    }
    
    @Override
    public void run() throws Exception {
        println("GhidRift: Extracting Rust metadata...");
        
        RustMetadata metadata = new RustMetadata();
        
        // Extract all strings from the binary
        List<String> strings = extractStrings();
        println("Found " + strings.size() + " strings in binary");
        
        // Extract compiler commit hash
        metadata.commitHash = extractCommitHash(strings);
        if (metadata.commitHash != null) {
            println("Found Rust compiler commit hash: " + metadata.commitHash);
        } else {
            println("No Rust compiler commit hash found");
        }
        
        // Extract crate information
        metadata.crates = extractCrates(strings);
        println("Found " + metadata.crates.size() + " Rust crates");
        for (String crate : metadata.crates) {
            println("  - " + crate);
        }
        
        // Determine target triple components
        metadata.arch = getArchitecture();
        metadata.os = getOperatingSystem();
        metadata.env = getEnvironment(strings);
        metadata.targetTriple = buildTargetTriple(metadata);
        
        println("\nTarget Triple: " + metadata.targetTriple);
        println("  Architecture: " + metadata.arch);
        println("  OS: " + metadata.os);
        println("  Environment: " + (metadata.env != null ? metadata.env : "none"));
        
        // Export metadata to file
        File outputFile = getOutputFile();
        if (outputFile != null) {
            exportMetadata(metadata, outputFile);
            println("\nMetadata exported to: " + outputFile.getAbsolutePath());
        } else {
            println("ERROR: Could not determine output file path");
        }
    }
    
    private List<String> extractStrings() throws MemoryAccessException {
        List<String> strings = new ArrayList<>();
        
        // Get defined string data
        DataIterator dataIterator = currentProgram.getListing().getDefinedData(true);
        while (dataIterator.hasNext()) {
            Data data = dataIterator.next();
            DataType dataType = data.getDataType();
            if (dataType instanceof StringDataType) {
                Object value = data.getValue();
                if (value != null) {
                    strings.add(value.toString());
                }
            }
        }
        
        // Also search for ASCII strings in memory
        Memory memory = currentProgram.getMemory();
        for (MemoryBlock block : memory.getBlocks()) {
            if (block.isInitialized()) {
                strings.addAll(findStringsInBlock(block));
            }
        }
        
        return strings;
    }
    
    private List<String> findStringsInBlock(MemoryBlock block) throws MemoryAccessException {
        List<String> strings = new ArrayList<>();
        Address start = block.getStart();
        Address end = block.getEnd();
        
        StringBuilder currentString = new StringBuilder();
        Address addr = start;
        
        while (addr.compareTo(end) <= 0) {
            byte b = getByte(addr);
            
            // Check if printable ASCII
            if (b >= 32 && b <= 126) {
                currentString.append((char) b);
            } else {
                // End of string
                if (currentString.length() >= 4) { // Minimum string length
                    strings.add(currentString.toString());
                }
                currentString = new StringBuilder();
            }
            
            addr = addr.add(1);
        }
        
        // Don't forget last string
        if (currentString.length() >= 4) {
            strings.add(currentString.toString());
        }
        
        return strings;
    }
    
    private String extractCommitHash(List<String> strings) {
        for (String str : strings) {
            Matcher matcher = RE_COMMITHASH.matcher(str);
            if (matcher.find()) {
                return matcher.group(1);
            }
        }
        return null;
    }
    
    private List<String> extractCrates(List<String> strings) {
        Set<String> crates = new HashSet<>();
        
        for (String str : strings) {
            Matcher matcher = RE_RUSTLIB.matcher(str);
            if (matcher.find()) {
                String crateInfo = matcher.group(1);
                crates.add(crateInfo);
            }
        }
        
        // Sort the crates for consistent output
        List<String> sortedCrates = new ArrayList<>(crates);
        Collections.sort(sortedCrates);
        return sortedCrates;
    }
    
    private String getArchitecture() {
        String processor = currentProgram.getLanguage().getProcessor().toString().toLowerCase();
        int pointerSize = currentProgram.getDefaultPointerSize();
        
        if (processor.contains("x86")) {
            if (pointerSize == 8) {
                return "x86_64";
            } else if (pointerSize == 4) {
                return "i686";
            }
        } else if (processor.contains("aarch64")) {
            return "aarch64";
        } else if (processor.contains("arm")) {
            return "arm";
        }
        
        return processor;
    }
    
    private String getOperatingSystem() {
        String format = currentProgram.getExecutableFormat().toLowerCase();
        
        if (format.contains("pe") || format.contains("coff")) {
            return "windows";
        } else if (format.contains("elf")) {
            return "linux";
        } else if (format.contains("mach")) {
            return "darwin";
        } else {
            return "unknown";
        }
    }
    
    private String getEnvironment(List<String> strings) {
        // Check for specific environment indicators
        for (String str : strings) {
            for (Map.Entry<String, String> entry : ENV_STRINGS.entrySet()) {
                if (str.contains(entry.getKey())) {
                    return entry.getValue();
                }
            }
        }
        
        // Default environments based on OS
        String os = getOperatingSystem();
        if ("windows".equals(os)) {
            // Could be msvc or gnu, default to msvc
            return "msvc";
        } else if ("linux".equals(os)) {
            return "gnu";
        }
        
        return null;
    }
    
    private String buildTargetTriple(RustMetadata metadata) {
        List<String> parts = new ArrayList<>();
        
        // Architecture
        parts.add(metadata.arch != null ? metadata.arch : "unknown");
        
        // Vendor (usually 'pc' for x86/x64, 'unknown' for others)
        if ("x86_64".equals(metadata.arch) || "i686".equals(metadata.arch)) {
            parts.add("pc");
        } else {
            parts.add(metadata.vendor);
        }
        
        // Operating system
        parts.add(metadata.os != null ? metadata.os : "unknown");
        
        // Environment/ABI (optional)
        if (metadata.env != null) {
            parts.add(metadata.env);
        }
        
        return String.join("-", parts);
    }
    
    private File getOutputFile() {
        try {
            // Get the executable path from the current program
            String executablePath = currentProgram.getExecutablePath();
            if (executablePath == null || executablePath.isEmpty()) {
                println("WARNING: Could not get executable path from program, trying alternative method");
                // Try to get from program name
                String programName = currentProgram.getName();
                if (programName != null && !programName.isEmpty()) {
                    // Use current working directory as fallback
                    executablePath = System.getProperty("user.dir") + File.separator + programName;
                } else {
                    return null;
                }
            }
            
            File executableFile = new File(executablePath);
            File parentDir = executableFile.getParentFile();
            if (parentDir == null) {
                parentDir = new File(System.getProperty("user.dir"));
            }
            
            // Create output filename based on executable name
            String execName = executableFile.getName();
            String baseName = execName.contains(".") ? 
                execName.substring(0, execName.lastIndexOf('.')) : execName;
            String outputFileName = baseName + "_metadata.json";
            
            return new File(parentDir, outputFileName);
            
        } catch (Exception e) {
            println("ERROR: Exception while determining output file: " + e.getMessage());
            return null;
        }
    }
    
    private void exportMetadata(RustMetadata metadata, File outputFile) throws IOException {
        try (FileWriter writer = new FileWriter(outputFile)) {
            writer.write(metadata.toJson());
        }
    }
}
