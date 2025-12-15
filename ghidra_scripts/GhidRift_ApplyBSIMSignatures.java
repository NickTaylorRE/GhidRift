/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
// GhidRift: Apply BSIM signatures to all functions in the current program
// This script queries a BSIM database and automatically applies function names
// from the highest confidence matches above a user-specified threshold
//@category BSim

import java.net.URL;
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.features.bsim.query.*;
import ghidra.features.bsim.query.description.*;
import ghidra.features.bsim.query.protocol.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.SourceType;
import ghidra.framework.Application;
import java.io.File;
import java.util.Arrays;
import java.util.List;
import java.util.ArrayList;
import java.util.Iterator;

public class GhidRift_ApplyBSIMSignatures extends GhidraScript {

	private static final int MATCHES_PER_FUNC = 10;
	private static final double SELF_SIGNIFICANCE_BOUND = 15.0;

	private String buildDatabasePrompt() {
		StringBuilder prompt = new StringBuilder();
		prompt.append("Enter BSIM database URL\n");
		prompt.append("Examples:\n");
		prompt.append("  - file:///path/to/database.bsim (local H2 database)\n");
		prompt.append("  - postgresql://host:port/dbname (PostgreSQL)\n");
		prompt.append("  - elastic://host:port (Elasticsearch)\n");
		
		// Check for GhidRift databases in common locations
		String homeDir = System.getProperty("user.home");
		File ghidriftDir = new File(homeDir, ".ghidrift");
		if (ghidriftDir.exists() && ghidriftDir.isDirectory()) {
			File[] bsimFiles = ghidriftDir.listFiles((dir, name) -> name.endsWith(".bsim"));
			if (bsimFiles != null && bsimFiles.length > 0) {
				prompt.append("\nFound GhidRift databases:\n");
				for (File bsimFile : bsimFiles) {
					prompt.append("  - file://").append(bsimFile.getAbsolutePath()).append("\n");
				}
			}
		}
		
		// Check current directory
		File currentDir = new File(".");
		File[] localBsimFiles = currentDir.listFiles((dir, name) -> name.endsWith(".bsim"));
		if (localBsimFiles != null && localBsimFiles.length > 0) {
			prompt.append("\nFound local databases:\n");
			for (File bsimFile : localBsimFiles) {
				prompt.append("  - file://").append(bsimFile.getAbsolutePath()).append("\n");
			}
		}
		
		String lastDbUrl = System.getProperty("ghidrift.bsim.lastdb", "");
		if (!lastDbUrl.isEmpty()) {
			prompt.append("\nLast used: ").append(lastDbUrl);
		}
		
		return prompt.toString();
	}

	@Override
	public void run() throws Exception {
		if (currentProgram == null) {
			popup("No program is open!");
			return;
		}

		// Ask user how they want to select the database
		List<String> options = new ArrayList<>();
		options.add("Browse for file");
		options.add("Enter URL manually");
		
		String lastDbUrl = System.getProperty("ghidrift.bsim.lastdb", "");
		if (!lastDbUrl.isEmpty()) {
			options.add("Use last database");
		}
		
		String choice = askChoice("Select BSIM Database", 
			"How would you like to select the BSIM database?", 
			options, options.get(0));
		
		String databaseUrl = "";
		
		if (choice.equals("Browse for file")) {
			// Use file browser
			File dbFile = askFile("Select BSIM Database File", "Select");
			if (dbFile == null) {
				popup("No file selected");
				return;
			}
			// Check if it's a BSIM database file
			if (!dbFile.getName().endsWith(".bsim") && !dbFile.getName().endsWith(".mv.db")) {
				boolean proceed = askYesNo("File Extension Warning", 
					"Selected file doesn't have .bsim extension. Continue anyway?");
				if (!proceed) {
					return;
				}
			}
			databaseUrl = "file://" + dbFile.getAbsolutePath();
			println("Selected database: " + databaseUrl);
			
		} else if (choice.equals("Enter URL manually")) {
			// Manual entry with helpful prompt
			String databasePrompt = buildDatabasePrompt();
			databaseUrl = askString("BSIM Database URL", databasePrompt);
			
			if (databaseUrl.isEmpty()) {
				popup("No database URL provided");
				return;
			}
			
		} else if (choice.equals("Use last database")) {
			// Use last database
			databaseUrl = lastDbUrl;
			println("Using last database: " + databaseUrl);
		}
		
		// Save the database URL for next time
		System.setProperty("ghidrift.bsim.lastdb", databaseUrl);
		
		// Get similarity threshold from user
		double similarityThreshold = askDouble("Similarity Threshold", 
			"Enter minimum similarity threshold (0.0 - 1.0):");
		
		if (similarityThreshold < 0.0 || similarityThreshold > 1.0) {
			popup("Similarity threshold must be between 0.0 and 1.0");
			return;
		}
		
		// Get confidence threshold from user
		double confidenceThreshold = askDouble("Confidence Threshold", 
			"Enter minimum confidence/significance threshold (e.g., 0.0):");
		
		// Ask if user wants to see what will be renamed before applying
		boolean previewMode = askYesNo("Preview Mode", 
			"Preview matches before applying? (Recommended for first run)");

		URL url = BSimClientFactory.deriveBSimURL(databaseUrl);
		
		println("Connecting to BSIM database: " + databaseUrl);
		println("Similarity threshold: " + similarityThreshold);
		println("Confidence threshold: " + confidenceThreshold);
		println("Preview mode: " + previewMode);
		println("");
		
		try (FunctionDatabase database = BSimClientFactory.buildClient(url, false)) {
			if (!database.initialize()) {
				popup("Failed to initialize database: " + database.getLastError().message);
				return;
			}
			
			// Generate signatures for all functions in the program
			Map<Function, Match> bestMatches = new HashMap<>();
			int processedFunctions = 0;
			int skippedFunctions = 0;
			
			// First, collect all functions that need processing
			List<Function> functionsToProcess = new ArrayList<>();
			FunctionIterator funcIter = currentProgram.getFunctionManager().getFunctionsNoStubs(true);
			
			while (funcIter.hasNext()) {
				Function func = funcIter.next();
				// Skip functions that already have meaningful names (not FUN_*)
				if (!func.getName().startsWith("FUN_")) {
					skippedFunctions++;
					continue;
				}
				functionsToProcess.add(func);
			}
			
			if (functionsToProcess.isEmpty()) {
				popup("No unnamed functions (FUN_*) found to process");
				return;
			}
			
			println("Found " + functionsToProcess.size() + " unnamed functions to process");
			
			// Process functions in batches to avoid the settings issue
			int batchSize = 100;
			int totalProcessed = 0;
			
			for (int start = 0; start < functionsToProcess.size(); start += batchSize) {
				if (monitor.isCancelled()) {
					break;
				}
				
				int end = Math.min(start + batchSize, functionsToProcess.size());
				List<Function> batch = functionsToProcess.subList(start, end);
				
				// Create a new GenSignatures for each batch
				GenSignatures gensig = new GenSignatures(false);
				try {
					gensig.setVectorFactory(database.getLSHVectorFactory());
					gensig.openProgram(currentProgram, null, null, null, null, null);
					
					monitor.setMessage("Processing batch " + (start/batchSize + 1) + " of " + 
						((functionsToProcess.size() + batchSize - 1) / batchSize));
					
					// Scan all functions in this batch
					gensig.scanFunctions(batch.iterator(), batch.size(), monitor);
					
					if (monitor.isCancelled()) {
						break;
					}
					
					// Get the description manager with all functions
					DescriptionManager descManager = gensig.getDescriptionManager();
					Iterator<FunctionDescription> descIter = descManager.listAllFunctions();
					
					// Process each function description
					while (descIter.hasNext()) {
						FunctionDescription funcDesc = descIter.next();
						
						// Find the corresponding Function object
						Function func = null;
						for (Function f : batch) {
							if (f.getEntryPoint().getOffset() == funcDesc.getAddress()) {
								func = f;
								break;
							}
						}
						
						if (func == null) {
							continue;
						}
						
						// Check self-significance
						double selfSig = database.getLSHVectorFactory()
							.getSelfSignificance(funcDesc.getSignatureRecord().getLSHVector());
						if (selfSig < SELF_SIGNIFICANCE_BOUND) {
							skippedFunctions++;
							continue;
						}
						
						// Create a new description manager with just this function
						DescriptionManager singleManager = new DescriptionManager();
						
						// Scan just this function to get it in the single manager
						GenSignatures tempGen = new GenSignatures(false);
						try {
							tempGen.setVectorFactory(database.getLSHVectorFactory());
							tempGen.openProgram(currentProgram, null, null, null, null, null);
							tempGen.scanFunction(func);
							
							// Query for similar functions
							QueryNearest query = new QueryNearest();
							query.manage = tempGen.getDescriptionManager();
							query.max = MATCHES_PER_FUNC;
							query.thresh = similarityThreshold;
							query.signifthresh = confidenceThreshold;
							
							ResponseNearest response = query.execute(database);
							if (response == null) {
								println("Query failed for " + func.getName() + ": " + database.getLastError().message);
								continue;
							}
							
							// Find the best match
							Match bestMatch = findBestMatch(response, func);
							if (bestMatch != null) {
								bestMatches.put(func, bestMatch);
							}
							
							processedFunctions++;
							totalProcessed++;
							
							if (totalProcessed % 10 == 0) {
								monitor.setMessage("Processed " + totalProcessed + " functions, found " + 
									bestMatches.size() + " matches");
							}
							
						} finally {
							tempGen.dispose();
						}
					}
					
				} catch (Exception e) {
					println("Error processing batch: " + e.getMessage());
					e.printStackTrace();
				} finally {
					gensig.dispose();
				}
			}
			
			if (monitor.isCancelled()) {
				println("Operation cancelled by user");
				return;
			}
			
			// Report results
			println("\nQuery Results:");
			println("Total functions: " + currentProgram.getFunctionManager().getFunctionCount());
			println("Processed functions: " + processedFunctions);
			println("Skipped functions (already named or low significance): " + skippedFunctions);
			println("Functions with matches: " + bestMatches.size());
			
			if (bestMatches.isEmpty()) {
				popup("No matches found above the specified thresholds");
				return;
			}
			
			// Preview or apply matches
			if (previewMode) {
				showPreview(bestMatches);
			} else {
				applyMatches(bestMatches);
			}
		}
	}
	
	private Match findBestMatch(ResponseNearest response, Function sourceFunc) {
		Match bestMatch = null;
		double bestSignificance = 0.0;
		
		for (SimilarityResult simResult : response.result) {
			for (SimilarityNote note : simResult) {
				// Skip if it's matching itself (same executable and function name)
				FunctionDescription funcDesc = note.getFunctionDescription();
				ExecutableRecord exeRec = funcDesc.getExecutableRecord();
				
				if (exeRec.getNameExec().equals(currentProgram.getName()) &&
					funcDesc.getFunctionName().equals(sourceFunc.getName())) {
					continue;
				}
				
				// Keep track of the highest significance match
				if (note.getSignificance() > bestSignificance) {
					bestSignificance = note.getSignificance();
					bestMatch = new Match(funcDesc.getFunctionName(), 
						exeRec.getNameExec(),
						note.getSimilarity(), 
						note.getSignificance());
				}
			}
		}
		
		return bestMatch;
	}
	
	private void showPreview(Map<Function, Match> matches) {
		StringBuilder preview = new StringBuilder();
		preview.append("\nProposed function renames:\n");
		preview.append("=====================================\n\n");
		
		// Sort by address for consistent display
		List<Function> sortedFuncs = new ArrayList<>(matches.keySet());
		sortedFuncs.sort((a, b) -> a.getEntryPoint().compareTo(b.getEntryPoint()));
		
		for (Function func : sortedFuncs) {
			Match match = matches.get(func);
			preview.append(String.format("%-40s -> %-40s (sim: %.3f, sig: %.3f) [%s]\n",
				func.getName(),
				match.functionName,
				match.similarity,
				match.significance,
				match.executableName));
		}
		
		preview.append("\nTotal functions to rename: ").append(matches.size()).append("\n");
		
		// Show preview and ask for confirmation
		println(preview.toString());
		
		boolean proceed = askYesNo("Apply Matches", 
			"Apply these " + matches.size() + " function renames?");
		
		if (proceed) {
			applyMatches(matches);
		} else {
			println("Operation cancelled - no changes made");
		}
	}
	
	private void applyMatches(Map<Function, Match> matches) {
		int renamed = 0;
		int failed = 0;
		
		monitor.initialize(matches.size());
		monitor.setMessage("Applying function names...");
		
		int id = currentProgram.startTransaction("GhidRift: Apply BSIM Signatures");
		try {
			for (Map.Entry<Function, Match> entry : matches.entrySet()) {
				if (monitor.isCancelled()) {
					break;
				}
				
				Function func = entry.getKey();
				Match match = entry.getValue();
				
				try {
					// Apply the matched function name
					func.setName(match.functionName, SourceType.IMPORTED);
					
					// Add a comment with match details
					String comment = String.format(
						"BSIM Match: %s (similarity: %.3f, significance: %.3f) from %s",
						match.functionName, match.similarity, match.significance, match.executableName);
					func.setComment(comment);
					
					renamed++;
					monitor.incrementProgress(1);
				} catch (Exception e) {
					println("Failed to rename " + func.getName() + " to " + match.functionName + ": " + e.getMessage());
					failed++;
				}
			}
			
			currentProgram.endTransaction(id, true);
			
			println("\nRename Results:");
			println("Successfully renamed: " + renamed);
			println("Failed: " + failed);
			
			if (renamed > 0) {
				popup("Successfully renamed " + renamed + " functions");
			}
			
		} catch (Exception e) {
			currentProgram.endTransaction(id, false);
			popup("Error applying matches: " + e.getMessage());
		}
	}
	
	// Helper class to store match information
	private static class Match {
		String functionName;
		String executableName;
		double similarity;
		double significance;
		
		Match(String functionName, String executableName, double similarity, double significance) {
			this.functionName = functionName;
			this.executableName = executableName;
			this.similarity = similarity;
			this.significance = significance;
		}
	}
}