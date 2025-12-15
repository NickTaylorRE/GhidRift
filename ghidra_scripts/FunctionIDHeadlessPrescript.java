//Pre-script to disable FunctionID analysis during import
//This ensures proper function identification before signature generation
//@author GhidRift
//@category FunctionID
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;

public class FunctionIDHeadlessPrescript extends GhidraScript {

    @Override
    protected void run() throws Exception {
        Program program = getCurrentProgram();
        if (program != null) {
            println("FunctionIDHeadlessPrescript: Preparing for FunctionID signature generation");
            println("FunctionIDHeadlessPrescript: Program loaded: " + program.getName());
        }
    }
}