//Post-script to validate functions after import
//This ensures proper function analysis before signature generation
//@author GhidRift
//@category FunctionID
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class FunctionIDHeadlessPostscript extends GhidraScript {

    @Override
    protected void run() throws Exception {
        Program program = getCurrentProgram();
        if (program != null) {
            println("FunctionIDHeadlessPostscript: Validating functions after import");
            
            // Get function manager
            FunctionManager functionManager = program.getFunctionManager();
            
            // Count functions
            int functionCount = functionManager.getFunctionCount();
            println("FunctionIDHeadlessPostscript: Found " + functionCount + " functions");
            
            if (functionCount == 0) {
                printerr("WARNING: No functions found after analysis!");
            }
        }
    }
}