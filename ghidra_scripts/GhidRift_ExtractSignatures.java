//Extract function signatures from object files for FunctionID generation
//This is a simplified headless-compatible version that processes one program at a time
//@author GhidRift
//@category FunctionID
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.AddressSetView;
import java.io.*;

public class GhidRift_ExtractSignatures extends GhidraScript {
    
    @Override
    public void run() throws Exception {
        // This is a marker script that just validates the program has functions
        // The actual FID database creation should be done using Ghidra's built-in tools
        // after collecting all the programs
        
        String outputPath = getScriptArgs().length > 0 ? getScriptArgs()[0] : "validation.txt";
        
        println("GhidRift: Validating program for FunctionID extraction");
        
        FunctionManager functionManager = currentProgram.getFunctionManager();
        int functionCount = functionManager.getFunctionCount();
        
        if (functionCount == 0) {
            printerr(currentProgram.getName() + " has no functions");
            return;
        }
        
        // Count functions that meet minimum size requirement
        int validFunctions = 0;
        FunctionIterator functions = functionManager.getFunctions(true);
        while (functions.hasNext()) {
            Function function = functions.next();
            if (!function.isThunk() && !function.isExternal()) {
                AddressSetView body = function.getBody();
                if (body.getNumAddresses() >= 6) { // Minimum 6 bytes
                    validFunctions++;
                }
            }
        }
        
        println("Program: " + currentProgram.getName());
        println("Total functions: " + functionCount);
        println("Valid functions for FID: " + validFunctions);
        println("Language: " + currentProgram.getLanguageID());
        println("Compiler: " + currentProgram.getCompilerSpec().getCompilerSpecID());
        
        // Write validation info to file
        try (PrintWriter writer = new PrintWriter(new FileWriter(outputPath, true))) {
            writer.println(currentProgram.getName() + "," + functionCount + "," + validFunctions);
        }
    }
}