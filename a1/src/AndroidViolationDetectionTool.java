import soot.Body;
import soot.Local;
import soot.PackManager;
import soot.RefType;
import soot.Scene;
import soot.SootClass;
import soot.SootField;
import soot.SootMethod;
import soot.SootMethodRef;
import soot.Type;
import soot.Unit;
import soot.Value;
import soot.ValueBox;
import soot.JastAddJ.SynchronizedStmt;
import soot.jimple.AssignStmt;
import soot.jimple.EnterMonitorStmt;
import soot.jimple.ExitMonitorStmt;
import soot.jimple.GotoStmt;
import soot.jimple.IfStmt;
import soot.jimple.InstanceInvokeExpr;
import soot.jimple.IntConstant;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;
import soot.jimple.JimpleBody;
import soot.jimple.MonitorStmt;
import soot.jimple.NewExpr;
import soot.jimple.SpecialInvokeExpr;
import soot.jimple.StaticFieldRef;
import soot.jimple.StaticInvokeExpr;
import soot.jimple.Stmt;
import soot.jimple.StringConstant;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.options.Options;
import soot.tagkit.SourceFileTag;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.toolkits.scalar.SimpleLocalDefs;
import soot.util.Chain;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;



public class AndroidViolationDetectionTool {
	private final static String USER_HOME = System.getProperty("user.home");
	
    private static String androidJar = USER_HOME + "/Library/Android/sdk/platforms";
    static String androidDemoPath = System.getProperty("user.dir") + File.separator + "Demo" + File.separator + "Android";
    //static String apkPath = androidDemoPath + File.separator + "/basic_financial_application.apk";
    
    static String apkFileName = "/wordpress.apk";
    
    static String apkPath = androidDemoPath + File.separator + apkFileName;
    
    static String outputPath = androidDemoPath + File.separator + "/Instrumented";
    
    
    private static void listAllClassesAndMethods() {
        System.out.println("Listing all classes and methods in the APK:");
        boolean isClassFound = false;
        for (SootClass sootClass : Scene.v().getApplicationClasses()) { 
            System.out.println("Class: " + sootClass.getName());
//            for (SootMethod method : sootClass.getMethods()) {
//            	isClassFound = true;
//                System.out.println("\tMethod: " + method.getSignature());
//            }           
        }
    }
    
    private static void analyze() {
        System.out.println("Analyzing APK " + apkFileName.toString()  + " for violations...");
        for (SootClass sootClass : Scene.v().getApplicationClasses()) { // Iterate over all application classes
        	
        	if(!sootClass.isConcrete()) {
        		try {
        		// violation 23
        		analyzePotentialMemoryLeaksDueToHandlers(sootClass); 
        		
        		// caution 11
               analyzeSnapHelperSubclass(sootClass); 
        		
        		  // violation 15
                detectPotentialInstanceCountViolations(sootClass);
                 
                 
                 // violation 16
                analyzeUriBasedFileAccess(sootClass); 
        		
        		 // violation 20
                
                
                 analyzePotentialANR(sootClass); 
        		
        		 // violation 19
                
                analyzePotentialStorageAccess(sootClass); 
                // violation 22
                analyzePotentialDeadlocks(sootClass); 
                
        		}catch (Exception e) {
                	//System.err.println("Error retrieving body for method: " + method.getSignature());
            		continue;
            	    
            	    //e.printStackTrace(); // Print detailed exception information
            	}
                 
        	}
        	
            for (SootMethod method : sootClass.getMethods()) {
            	
                if (method.isConcrete()) { // Ensure the method has a body to analyze
                	
                	try {
                		Body body = method.retrieveActiveBody();
                	    
                		detectIntentDataAndTypeIssue(body,method);
                		
	             	    detectParcelableSerializableUsage(body,method);
	             	    
	             	    
	            	    
	            	    analyzeIntentFilterUsage(sootClass);
            	    
                	    analyzeMethodForHttpUsage(body);
                	    
                	    analyzeMethodForLayoutInflaterUsage(method);
                	    
	                    
	                    // caution 7
	                    
	                  
	                    
	                    
	                    // caution 11.1
	                    
	                    //analyzeMethodForInsecureSSL(body, method); 
	                   
	                    // violatio 14
	                    
	                    
	                    /*
	                    JimpleBody jimpleBody = (JimpleBody) method.retrieveActiveBody();
	                    
	                    if (callsSslErrorHandlerProceed(jimpleBody)) {
	                        System.out.println("Direct violation found in " + method.getSignature());
	                    }
	                    
	                    performInterProceduralAnalysis(method);
	                    
	                     */
	                  
	                    // violatio 17
	                    
	                    
	                   // mightRunOnMainThread(body); 
	                    
	                    // detectExplicitIntentUsage(body,method);
	                    
	                   
	                    /*
	                    if (isAsyncTaskSubclass(sootClass)) {
	                        for (SootMethod method1 : sootClass.getMethods()) {
	                            if (method1.getName().equals("doInBackground")) {
	                                analyzeDoInBackgroundForAsyncTaskExecution(method1);
	                            }
	                        }
	                    }
	                    */

               }
             catch (Exception e) {
                	//System.err.println("Error retrieving body for method: " + method.getSignature());
            		continue;
            	    
            	    //e.printStackTrace(); // Print detailed exception information
            	}
            }
        }
        }
        
        
    
        System.out.println("analysis completed");
    }
    
    public static void main(String[] args) {
    	
    	
    	Options.v().set_allow_phantom_refs(true);
        Options.v().set_whole_program(true);
        Options.v().set_process_multiple_dex(true);
        Options.v().set_prepend_classpath(true); // Added option
        //Options.v().setPhaseOption("cg.spark", "on");
        
        Options.v().set_src_prec(Options.src_prec_apk);
        
        File apkFile = new File(apkPath);
        if (!apkFile.exists()) {
            System.err.println("Error: APK file does not exist at the specified path: " + apkPath);
            return; // Exit or handle the error appropriately
        }
        else {
        	System.out.println("APK File existed");
        }

        
        Options.v().set_process_dir(Collections.singletonList(apkPath));
        if(System.getenv().containsKey("ANDROID_HOME"))
            androidJar = System.getenv("ANDROID_HOME") + File.separator + "platforms";
        Options.v().set_android_jars(androidJar);
        
        
        Options.v().set_process_multiple_dex(true);
        
        Options.v().set_validate(true);
        
        Scene.v().addBasicClass("java.io.PrintStream", SootClass.SIGNATURES);
        Scene.v().addBasicClass("java.lang.System", SootClass.SIGNATURES);
        
        Scene.v().loadNecessaryClasses();
        
        
        Options.v().set_verbose(false);

        
        System.out.println("Soot setup completed.");
        
        
        //listAllClassesAndMethods();
        analyze();
       
    }
    
    private static void detectIntentDataAndTypeIssue(Body body, SootMethod method) {
        boolean setDataCalled = false;
        boolean setTypeCalled = false;
       
        List<Unit> setDataUnits = new ArrayList<>();
        List<Unit> setTypeUnits = new ArrayList<>();
        
        for (Unit unit : body.getUnits()) {
            Stmt stmt = (Stmt) unit;
            if (stmt.containsInvokeExpr()) {
                InvokeExpr invokeExpr = stmt.getInvokeExpr();
                String methodName = invokeExpr.getMethod().getName();

                if (methodName.equals("setData")) {
                    setDataCalled = true;
                    setDataUnits.add(unit);
                } else if (methodName.equals("setType")) {
                    setTypeCalled = true;
                    setTypeUnits.add(unit);
                }

                if (setDataCalled && setTypeCalled) {
                	int lineNumber = unit.getJavaSourceStartLineNumber();
                	
                	 String redStart = "\u001B[31m";
                     String redEnd = "\u001B[0m";
                     System.out.println(redStart + "Security Violation Detected: Use of setData and setType Separately" + redEnd);
                     
                     //System.out.println("Class: " + method.getDeclaringClass().getName());
                     System.out.println("Method: " + method.getName());
                     System.out.println("Issue: Separate calls to setData and setType on the same Intent object.");
                     System.out.println("Location: " + method.getDeclaringClass().getName() + " -> " + method.getName());

                     // Show code snippets for setData and setType calls
                     System.out.println("Code Snippet for setData:");
                     setDataUnits.forEach(unit1 -> System.out.println("  " + unit));
                     System.out.println("Code Snippet for setType:");
                     setTypeUnits.forEach(unit1 -> System.out.println("  " + unit));

                     System.out.println("Recommendations:");
                     System.out.println("- Combine setData and setType calls into a single setDataAndType call for improved security.");
                     System.out.println();
                     
                     SootClass sootClass = method.getDeclaringClass();
                     if (sootClass.hasTag("SourceFileTag")) {
                         SourceFileTag tag = (SourceFileTag) sootClass.getTag("SourceFileTag");
                         String sourceFileName = tag.getSourceFile();
                         System.out.println("Source File: " + sourceFileName);
                     }

                     
                    break;
                    
                }
            }
        }
        
        
    }
    
 /*  Caution 3 */
    
    public static void detectParcelableSerializableUsage(Body body, SootMethod method) {
    	if (!method.isConcrete()) return;
        Chain<Unit> units = body.getUnits();
        // Stores local variables that refer to Bundle objects
        Set<Local> bundleLocals = new HashSet<>();
        
        boolean isNotFind = true;
        for (Unit unit : units) {
            if (unit instanceof AssignStmt) {
            	AssignStmt assignStmt = (AssignStmt) unit;
                Value rightOp = assignStmt.getRightOp();
                
                // Check for Bundle object creation
                if (rightOp instanceof NewExpr && ((NewExpr) rightOp).getBaseType().toString().equals("android.os.Bundle")) {
                	//System.out.println("coming into this1");
                	bundleLocals.add((Local) assignStmt.getLeftOp());
                }
            } else if (unit instanceof InvokeStmt || unit instanceof InvokeExpr) {
                InvokeExpr invokeExpr = unit instanceof InvokeStmt ? ((InvokeStmt) unit).getInvokeExpr() : (InvokeExpr) unit;
                
                if (invokeExpr instanceof InstanceInvokeExpr) {
                	
                    InstanceInvokeExpr instanceInvokeExpr = (InstanceInvokeExpr) invokeExpr;
                    Local base = (Local) instanceInvokeExpr.getBase();
                    
                    // Check if the invocation is on a Bundle instance and it's putExtra method
                    if (bundleLocals.contains(base) && invokeExpr.getMethodRef().name().equals("putExtra")) {
                    	
                    	Value arg = invokeExpr.getArg(1); // The second argument of putExtra
                        
                        if (arg.getType() instanceof RefType) {
                            RefType type = (RefType) arg.getType();
                            SootClass argClass = type.getSootClass();
                            
                            if (isParcelableOrSerializable(argClass)) {
                            	String redStart = "\u001B[31m";
                            	String redEnd = "\u001B[0m";
                            	
                            	System.out.println(redStart + "Security Violation Detected: Use of putExtra with Parcelable or Serializable Argument" + redEnd);
                               // System.out.println("Class: " + method.getDeclaringClass().getName());
                                System.out.println("Method: " + method.getName());
                                System.out.println("Issue: Found usage of putExtra with a Parcelable or Serializable argument.");
                                System.out.println("Location: " + method.getDeclaringClass().getName() + " -> " + method.getName() );
                                System.out.println("Recommendations:");
                                System.out.println("- Consider using alternative data transfer mechanisms to avoid potential security risks.");
                                System.out.println();
                                
                            	int lineNumber = unit.getJavaSourceStartLineNumber();
                                
                            }
                        }
                    }
                }
            }
        }
        
    }

    private static boolean isParcelableOrSerializable(SootClass argClass) {
        // Simplified check for Parcelable or Serializable. 
        // In reality, you would check if argClass is a subclass or implements Parcelable or Serializable.
        return Scene.v().getOrMakeFastHierarchy().canStoreType(argClass.getType(), Scene.v().getRefType("android.os.Parcelable")) ||
               Scene.v().getOrMakeFastHierarchy().canStoreType(argClass.getType(), Scene.v().getRefType("java.io.Serializable"));
        
        
        
    }
    
    
    
    private static void detectExplicitIntentUsage(Body body, SootMethod method) {
    	
    	boolean setDataCalled = false;
    	
    	boolean setTypeCalled = false;
    	  
    	List<Unit> explicitIntentUnits = new ArrayList<>();
    	
        for (Unit unit : body.getUnits()) {
            Stmt stmt = (Stmt) unit;
            // Check if the statement contains an InvokeExpr before proceeding.
            if (stmt.containsInvokeExpr()) {
                InvokeExpr invokeExpr = stmt.getInvokeExpr();
                
                String methodName = invokeExpr.getMethod().getName();
                
                if (invokeExpr.getMethod().getName().equals("startService") ||
                    invokeExpr.getMethod().getName().equals("bindService")) {
                    // This check ensures we only analyze statements with method calls.
                	explicitIntentUnits.add(unit);
                	//System.out.println("Check for explicit Intent usage in method: " + method.getSignature());
                }
            }
        }
        if (!explicitIntentUnits.isEmpty()) {
        	String redStart = "\u001B[31m";
            String redEnd = "\u001B[0m";
            System.out.println(redStart + "Explicit Intent Usage Detected" + redEnd);
            //System.out.println("Class: " + method.getDeclaringClass().getName());
            System.out.println("Method: " + method.getSubSignature());
            System.out.println("Issue: Possible use of explicit intents with startService or bindService.");
            System.out.println("Code Snippets:");
            
            int linesPrinted = 0;
            for (Unit explicitIntentUnit : explicitIntentUnits) {
                if (linesPrinted >= 7) break; // Limit the number of printed lines
                
                
                System.out.println("  " + explicitIntentUnit);
                linesPrinted++;
            }
        }
    }
    
    

    
   
    
    

    private static boolean isSubclassOf(SootClass sootClass, String className) {
        SootClass superClass = Scene.v().getSootClass(className);
        return Scene.v().getActiveHierarchy().isClassSubclassOfIncluding(sootClass, superClass);
    }

    private static void analyzeIntentFilterUsage(SootClass sootClass) {
        // Check if the class extends Activity, Service, or BroadcastReceiver
        boolean isActivity = isSubclassOf(sootClass, "android.app.Activity");
        boolean isService = isSubclassOf(sootClass, "android.app.Service");
        boolean isBroadcastReceiver = isSubclassOf(sootClass, "android.content.BroadcastReceiver");

        if (isActivity || isService || isBroadcastReceiver) {

            // Search for presence of intent-filter element in the manifest
            for (SootField field : sootClass.getFields()) {
                if (field.getName().equals("R$styleable") && field.getType().toString().equals("int[]")) {
                    // Assuming R.styleable.AndroidManifest_intentFilters is used (common practice)

                    // Check if the field is a static final field (assuming constant initialization)
                    if (field.isStatic() && field.isFinal()) {
                        SootMethod clinitMethod = findClinitMethod(sootClass);  // Use helper method to find the clinit method

                        if (clinitMethod != null) {
                            // Analyze the clinit method to find the constant assignment
                            Body body = clinitMethod.retrieveActiveBody();
                            for (Unit unit : body.getUnits()) {
                                if (unit instanceof AssignStmt) {
                                    AssignStmt assignStmt = (AssignStmt) unit;
                                    if (assignStmt.getLeftOp() instanceof StaticFieldRef &&
                                            ((StaticFieldRef) assignStmt.getLeftOp()).getFieldRef().equals(field)) {
                                        // Found the constant assignment
                                        Value rhs = assignStmt.getRightOp();
                                        if (rhs instanceof IntConstant) {
                                            int[] filterStyleable = new int[] {((IntConstant) rhs).value};  // Create the int array
                                            
                                            if (filterStyleable != null) {
                                                // Potential Caution 4 violation: class uses intent filters
                                                System.out.println("Potential Caution 4 Violation: " + sootClass.getName() +
                                                        " uses intent filters. Consider using exported=\"false\" for the component if only your app should start it.");
                                            }
                                        } else {
                                            // Handle the case where the value is not an IntConstant (less common)
                                            System.err.println("Unexpected constant type for R.styleable.AndroidManifest_intentFilters");
                                        }
                                        break; // Exit after finding the assignment
                                    }
                                }
                            }
                        } else {
                            System.err.println("Clinit method not found for R.styleable field");
                        }
                    } else {
                        System.err.println("R.styleable field is not static final");
                    }
                }
            }
        }
    }

    // Helper method to find the clinit method
    private static SootMethod findClinitMethod(SootClass sootClass) {
        for (SootMethod method : sootClass.getMethods()) {
            if (method.getName().equals("<clinit>")) {
                return method;
            }
        }
        return null;
    }


    
 // Helper function to check if a class extends BroadcastReceiver
    private static boolean isBroadcastReceiver(SootClass sootClass) {
        // Get the SootClass representation of BroadcastReceiver
        SootClass broadcastReceiverClass = Scene.v().getSootClass("android.content.BroadcastReceiver");

        // Check if sootClass is a subclass of BroadcastReceiver
        // This includes checking if sootClass is a direct subclass or further down the hierarchy
        return Scene.v().getActiveHierarchy().isClassSubclassOfIncluding(sootClass, broadcastReceiverClass);
    }


    private static void analyzeBroadcastReceiverRegistration(Body body, SootMethod method) {
      for (Unit unit : body.getUnits()) {
        Stmt stmt = (Stmt) unit;

        // Check for calls to registerReceiver
        if (stmt.containsInvokeExpr()) {
          InvokeExpr invokeExpr = stmt.getInvokeExpr();
          if (invokeExpr.getMethod().getName().equals("registerReceiver") &&
              invokeExpr.getMethodRef().getDeclaringClass().getName().equals("android.app.Context")) {
            // Track the registered receiver (assuming the first argument)
            Value receiverArg = invokeExpr.getArg(0);

            // Look for calls to unregisterReceiver within the same method
            boolean unregistered = false;
            for (Unit u : body.getUnits()) {
              Stmt s = (Stmt) u;
              if (s.containsInvokeExpr()) {
                InvokeExpr innerInvokeExpr = s.getInvokeExpr();
                if (innerInvokeExpr.getMethod().getName().equals("unregisterReceiver") &&
                    innerInvokeExpr.getMethodRef().getDeclaringClass().getName().equals("android.content.Context")) {
                  Value innerReceiverArg = innerInvokeExpr.getArg(0);
                  if (innerReceiverArg == receiverArg) {
                    unregistered = true;
                    break;
                  }
                }
              }
            }

            // Report potential violation if not unregistered
            if (!unregistered) {
              System.out.println("Potential Caution 5 Violation in " + method.getSignature() + 
                                 ": Registered a BroadcastReceiver but might not be unregistering it. Consider unregistering in onPause or onDestroy.");
            }
          }
        }
      }
    }

    private static final Set<String> sensitiveSourceSignatures = new HashSet<>(Arrays.asList(
            "getPassword", // Example method names that might return sensitive data
            "getToken",
            "getEncryptionKey"
        ));
    
    private static void analyzeMethodForSharedPreferencesTaint(Body body) {
    	
        Map<Local, Boolean> taintedLocals = new HashMap<>();
        
       
        
        
        for (Unit unit : body.getUnits()) {
        	
        	if (!(unit instanceof Stmt)) {
                continue; // Skip units that are not Jimple statements
            }
        	
            Stmt stmt = (Stmt) unit;

            // Detect sources of sensitive information
            if (stmt.containsInvokeExpr()) {
                InvokeExpr invokeExpr = stmt.getInvokeExpr();
                if (sensitiveSourceSignatures.contains(invokeExpr.getMethod().getName())) {
                    if (stmt instanceof AssignStmt) {
                        AssignStmt assignStmt = (AssignStmt) stmt;
                        Value leftOp = assignStmt.getLeftOp();
                        if (leftOp instanceof Local) {
                            taintedLocals.put((Local) leftOp, true);
                        }
                    }
                }
            }

            // Check SharedPreferences.Editor usage
            if (stmt.containsInvokeExpr()) {
                InvokeExpr invokeExpr = stmt.getInvokeExpr();
                if (invokeExpr instanceof InstanceInvokeExpr) {
                    InstanceInvokeExpr instanceInvokeExpr = (InstanceInvokeExpr) invokeExpr;
                    if (instanceInvokeExpr.getBase().getType().toString().equals("android.content.SharedPreferences$Editor")) {
                        if (invokeExpr.getMethod().getName().startsWith("put")) {
                            for (ValueBox vb : stmt.getUseBoxes()) {
                                Value value = vb.getValue();
                                if (value instanceof Local && taintedLocals.getOrDefault(value, false)) {
                                    // Found a potentially sensitive data being stored
                                    //System.out.println("Potential Caution 6 Violation: Sensitive data stored in SharedPreferences in method " + body.getMethod());
                                	String sourceFileName = getSourceFileName(body.getMethod().getDeclaringClass());
                                    String redStart = "\u001B[31m";
                                    String redEnd = "\u001B[0m";
                                    System.out.println(redStart + "Potential Caution 6 Violation Detected" + redEnd);
                                    //System.out.println("Class: " + body.getMethod().getDeclaringClass().getName());
                                    if (sourceFileName != null) {
                                        System.out.println("Source File: " + sourceFileName);
                                    }
                                    System.out.println("Issue: Sensitive data stored in SharedPreferences.");
                                    System.out.println("Location: Method " + body.getMethod().getSubSignature() + " in class " + body.getMethod().getDeclaringClass().getName());
                                    System.out.println("Code Snippet:");
                                    printCodeSnippet(body, unit); // This function needs to be implemented to print the relevant code snippet.
                                    System.out.println("Recommendations:");
                                    System.out.println("- Avoid storing sensitive information in SharedPreferences.");
                                    System.out.println("- Consider encrypting sensitive data before storage.");
                                    System.out.println();
                                	break;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    
    // caution 7 code
    
    private static void analyzeWebViewJavaScriptEnabling(SootMethod method) {
        Body body = method.retrieveActiveBody();
        ExceptionalUnitGraph graph = new ExceptionalUnitGraph(body);
        SimpleLocalDefs localDefs = new SimpleLocalDefs(graph);

        for (Unit unit : body.getUnits()) {
            Stmt stmt = (Stmt) unit;
            if (stmt.containsInvokeExpr()) {
                InvokeExpr invokeExpr = stmt.getInvokeExpr();
                String methodName = invokeExpr.getMethod().getName();
                if (methodName.equals("setJavaScriptEnabled") && isWebViewSettings(invokeExpr)) {
                    boolean isJavaScriptEnabled = isJavaScriptEnabled(stmt, localDefs);
                    if (isJavaScriptEnabled) {
                        String sourceFileName = getSourceFileName(method.getDeclaringClass());
                        String redStart = "\u001B[31m";
                        String redEnd = "\u001B[0m";

                        System.out.println(redStart + "Potential Security Risk Detected: JavaScript Enabled in WebView" + redEnd);
                        System.out.println("Class: " + method.getDeclaringClass().getName());
                        if (sourceFileName != null) {
                            System.out.println("Source File: " + sourceFileName);
                        }
                        System.out.println("Issue: JavaScript enabled via setJavaScriptEnabled(true) without adequate safeguards.");
                        System.out.println("Location: Method " + method.getSubSignature() + " in class " + method.getDeclaringClass().getName());
                        System.out.println("Code Snippet:");
                        printCodeSnippet(body, unit); // Assumes implementation that prints the relevant code snippet.
                        System.out.println("Recommendations:");
                        System.out.println("- Ensure JavaScript is only enabled for trusted content.");
                        System.out.println("- Use WebViewClient.shouldOverrideUrlLoading() to control URL loading.");
                        System.out.println("- Consider using additional security measures such as Content Security Policy (CSP).");
                        System.out.println();
                    }
                }
            }
        }
    }

    private static String getSourceFileName(SootClass sootClass) {
        SourceFileTag sourceFileTag = (SourceFileTag) sootClass.getTag("SourceFileTag");
        if (sourceFileTag != null) {
            return sourceFileTag.getSourceFile();
        }
        return null;
    }

    // Helper method implementations for `isWebViewSettings` and `isJavaScriptEnabled` are assumed.


    private static boolean isWebViewSettings(InvokeExpr invokeExpr) {
        // Implement logic to check if the invokeExpr is called on a WebSettings instance
        // This may involve analyzing the base object of the invokeExpr
        return true; // Simplified for illustration
    }

    private static boolean isJavaScriptEnabled(Stmt stmt, SimpleLocalDefs localDefs) {
        // Implement logic to check if the argument to setJavaScriptEnabled is true
        // This may involve analyzing the definitions of the argument value
        return true; // Simplified for illustration
    }
    
    

    

    
    
    
    
 // memory leaks violations code ( violation 3)
	
 	private static void analyzePotentialMemoryLeaks(SootClass sootClass) {
 	    if (!sootClass.isConcrete() || !isActivityClass(sootClass)) return;

 	    Set<SootClass> potentialLeakCauses = new HashSet<>();

 	    for (SootMethod method : sootClass.getMethods()) {
 	        if (method.isConcrete()) {
 	            Body body = method.retrieveActiveBody();
 	            for (Unit unit : body.getUnits()) {
 	                Stmt stmt = (Stmt) unit;

 	                if (stmt instanceof AssignStmt) {
 	                    Value rightOp = ((AssignStmt) stmt).getRightOp();
 	                    if (rightOp instanceof NewExpr) {
 	                        SootClass innerClass = ((NewExpr) rightOp).getBaseType().getSootClass();
 	                        if (innerClass.isInnerClass() && innerClass.getName().startsWith(sootClass.getName())) {
 	                            potentialLeakCauses.add(innerClass);
 	                        }
 	                    }
 	                } else if (stmt instanceof InvokeStmt) {
 	                    analyzeInvokeStatementForHandlers((InvokeStmt) stmt, potentialLeakCauses, sootClass);
 	                }
 	            }
 	        }
 	    }

 	    // Output potential leak causes with suggestions for fixes
 	    for (SootClass leakCause : potentialLeakCauses) {
 	        System.out.println("Potential memory leak through inner class: " + leakCause.getName() + 
 	                           ". Ensure proper cleanup (e.g., unregister listeners, stop handlers) in corresponding lifecycle methods.");
 	    }
 	}

 	private static void analyzeInvokeStatementForHandlers(InvokeStmt stmt, Set<SootClass> potentialLeakCauses, SootClass sootClass) {
 	    InvokeExpr invokeExpr = stmt.getInvokeExpr();
 	    if (invokeExpr.getMethod().getName().equals("postDelayed") && invokeExpr.getArgs().size() > 1) {
 	        Value runnableArg = invokeExpr.getArg(0);
 	        if (runnableArg instanceof Local) {
 	            Local runnableLocal = (Local) runnableArg;
 	            SootClass runnableClass = findClassFromLocal(runnableLocal, stmt);
 	            if (runnableClass != null && runnableClass.isInnerClass() && runnableClass.getName().startsWith(sootClass.getName())) {
 	                potentialLeakCauses.add(runnableClass);
 	            }
 	        }
 	    }
 	}

 	private static SootClass findClassFromLocal(Local local, Stmt context) {
 	    // Simplified. Implement a backward analysis to find the NewExpr for this local, then return its base type's SootClass.
 	    // This might involve a more complex data flow analysis to accurately track the Local's origin.
 	    return null;
 	}

 	private static boolean isActivityClass(SootClass sootClass) {
 	    // Check if sootClass is a subclass of android.app.Activity.
 	    return Scene.v().getActiveHierarchy().isClassSubclassOf(sootClass, Scene.v().getSootClass("android.app.Activity"));
 	}
 	
 	
 	// violation4
 	
 	private static void analyzeAsyncTaskUiUpdates(SootClass sootClass) {
 	    if (!sootClass.isConcrete()) {
 	        return; // Skip abstract classes
 	    }

 	    for (SootMethod method : sootClass.getMethods()) {
 	        if (!method.isConcrete()) {
 	            continue; // Skip non-concrete methods
 	        }

 	        Body body = method.retrieveActiveBody();
 	        Set<SootMethod> potentialViolationMethods = new HashSet<>(); // Corrected to Set<SootMethod>

 	        // Identify AsyncTask usage:
 	        for (Unit unit : body.getUnits()) {
 	            Stmt stmt = (Stmt) unit;
 	            if (stmt instanceof InvokeStmt) {
 	                InvokeExpr invokeExpr = ((InvokeStmt) stmt).getInvokeExpr();
 	                if (invokeExpr.getMethod().getName().equals("execute") &&
 	                    invokeExpr.getMethodRef().getDeclaringClass().getName().equals("android.os.AsyncTask")) {
 	                    potentialViolationMethods.add(method); // Correctly adding SootMethod objects
 	                }
 	            }
 	        }

 	        // Analyze potential violations:
 	        for (SootMethod potentialViolationMethod : potentialViolationMethods) {
 	            boolean leakCandidates = false;

 	            // 1. Check for Context or Activity usage within AsyncTask:
 	            for (Unit unit : potentialViolationMethod.retrieveActiveBody().getUnits()) {
 	                Stmt stmt = (Stmt) unit;
 	                if (stmt instanceof InvokeExpr) {
 	                    InvokeExpr invokeExpr = (InvokeExpr) stmt;
 	                    SootClass accessedClass = invokeExpr.getMethodRef().getDeclaringClass();
 	                    if (accessedClass.getName().startsWith("android.content.Context") ||
 	                        accessedClass.getName().startsWith("android.app.Activity")) {
 	                        leakCandidates = true;
 	                        break; // Early exit if Context or Activity is used
 	                    }
 	                }
 	            }

 	            // 2. Heuristic check for UI updates:
 	            if (!leakCandidates) {
 	                for (Unit unit : potentialViolationMethod.retrieveActiveBody().getUnits()) {
 	                    Stmt stmt = (Stmt) unit;
 	                    if (stmt instanceof InvokeStmt) {
 	                        InvokeExpr invokeExpr = (InvokeExpr) stmt;
 	                        String methodName = invokeExpr.getMethod().getName();
 	                        if (methodName.startsWith("set") || methodName.startsWith("update") ||
 	                            methodName.equals("runOnUiThread")) {
 	                            leakCandidates = true;
 	                            break; // Early exit if potential UI update methods are found
 	                        }
 	                    }
 	                }
 	            }

 	            if (leakCandidates) {
 	                System.out.println("Potential Caution 4 Violation in " + potentialViolationMethod.getSignature() +
 	                    ": AsyncTask might be updating the UI directly. Consider using a weak reference to the Context or Activity or employing mechanisms like Handler or LiveData to safely update the UI from a background thread.");
 	            }
 	        }
 	    }
 	}

 	// violation 2
 	
 	private static void analyzeMethodForSQLiteOperations(SootMethod method) {
         Body body = method.retrieveActiveBody();
         for (Unit unit : body.getUnits()) {
             Stmt stmt = (Stmt) unit;
             if (stmt.containsInvokeExpr()) {
                 InvokeExpr invokeExpr = stmt.getInvokeExpr();
                 if (isSQLiteOperation(invokeExpr)) {
                     System.out.println("Potential StrictMode Disk Write Violation in " + method.getSignature() + ": SQLite operation on UI thread.");
                 }
             }
         }
     }
 	
 	private static boolean isSQLiteOperation(InvokeExpr invokeExpr) {
         String methodName = invokeExpr.getMethod().getName();
         // This list can be expanded based on the operations you're interested in
         List<String> dbMethods = Arrays.asList("insert", "update", "delete", "execSQL");
         return dbMethods.contains(methodName) && invokeExpr.getMethod().getDeclaringClass().getName().startsWith("android.database.sqlite");
     }
     
     private static boolean isOnUiThreadClass(SootClass sootClass) {
         // Simplified check. A more comprehensive approach would involve checking the Android lifecycle
         return sootClass.getSuperclass().getName().equals("android.app.Activity") ||
                sootClass.getSuperclass().getName().equals("android.support.v4.app.Fragment") ||
                sootClass.getSuperclass().getName().equals("android.app.Fragment");
     }
     
     // violation 1
     
     private static void analyzeWebViewDiskReads(SootClass sootClass) {
         if (!sootClass.isConcrete()) return; // Skip abstract classes
         
         for (SootMethod method : sootClass.getMethods()) {
             if (isOnCreateMethod(method)) {
                 boolean webViewInteractionDetected = detectsWebViewInteraction(method);
                 if (webViewInteractionDetected) {
                     System.out.println("Potential StrictMode Disk Read Violation: " +
                         "WebView interaction detected in onCreate() of " + sootClass.getName() +
                         ". Review for disk read operations.");
                 }
             }
         }
     }

     private static boolean isOnCreateMethod(SootMethod method) {
    	    // Check if the method is named onCreate
    	    if (!method.getName().equals("onCreate")) {
    	        return false;
    	    }
    	    
    	    // Check if the method's declaring class or any of its superclasses is android.app.Activity
    	    SootClass currentClass = method.getDeclaringClass();
    	    while (currentClass.hasSuperclass()) { // Iterate through the superclass chain
    	        if (currentClass.getName().equals("android.app.Activity")) {
    	            return true; // Found that the current class or a superclass is android.app.Activity
    	        }
    	        currentClass = currentClass.getSuperclass(); // Move up in the inheritance hierarchy
    	    }
    	    
    	    return false; // The method's class does not extend android.app.Activity
    	}

     

     private static boolean detectsWebViewInteraction(SootMethod method) {
         if (!method.isConcrete()) return false; // Only concrete methods
         
         Body body = method.retrieveActiveBody();
         for (Unit unit : body.getUnits()) {
             if (unit instanceof AssignStmt) {
                 Value rightOp = ((AssignStmt) unit).getRightOp();
                 if (rightOp instanceof NewExpr && 
                     ((NewExpr) rightOp).getBaseType().toString().equals("android.webkit.WebView")) {
                     // Direct WebView instance creation detected
                     return true;
                 }
             } else if (unit instanceof InvokeStmt) {
                 InvokeExpr invokeExpr = ((InvokeStmt) unit).getInvokeExpr();
                 // Check for WebView method invocations that could imply an instance creation
                 if (invokeExpr.getMethod().getDeclaringClass().getName().equals("android.webkit.WebView")) {
                     return true;
                 }
             }
         }
         return false;
     }
     
     
 	// violation 5
     
     private static void analyzeContextLeak(SootClass sootClass) {
         // Iterate through all fields in the class
         for (SootField field : sootClass.getFields()) {
             // Check if the field is static and of type Context or its subclasses
             if (field.isStatic() && isContextType(field.getType())) {
                 System.out.println("Potential Memory Leak: Static field of type Context detected in " +
                     sootClass.getName() + ". Field: " + field.getName());
             }
         }
     }
     
     private static boolean isContextType(Type fieldType) {
         // Check if fieldType is a Context, Activity, or any subclass thereof
         if (fieldType instanceof RefType) {
             SootClass fieldClass = ((RefType) fieldType).getSootClass();
             // Check if fieldClass is Context, Activity, or one of their subclasses
             while (fieldClass != null) {
                 if (fieldClass.getName().equals("android.content.Context") ||
                     fieldClass.getName().equals("android.app.Activity")) {
                     return true;
                 }
                 // Move to the superclass to check if it's Context or Activity
                 if (!fieldClass.hasSuperclass()) break;
                 fieldClass = fieldClass.getSuperclass();
             }
         }
         return false;
     }
     
     // violation 6
     
     private static void analyzeWebViewUsage(SootClass sootClass) {
         // Iterate over all methods in the class
         for (SootMethod method : sootClass.getMethods()) {
             if (method.isConcrete()) { // Check if method has a body to analyze
                 Body body = method.retrieveActiveBody();
                 boolean webViewInstantiated = false;
                 
                 // Look for WebView instantiation
                 for (Unit unit : body.getUnits()) {
                     if (unit instanceof AssignStmt) {
                         AssignStmt assignStmt = (AssignStmt) unit;
                         Value rightOp = assignStmt.getRightOp();
                         if (rightOp instanceof NewExpr) {
                             NewExpr newExpr = (NewExpr) rightOp;
                             if (newExpr.getBaseType().toString().equals("android.webkit.WebView")) {
                                 webViewInstantiated = true;
                                 break;
                             }
                         }
                     }
                 }
                 
                 if (webViewInstantiated) {
                     // WebView is instantiated, check if onDestroy properly cleans it
                     SootMethod onDestroyMethod = findOnDestroyMethod(sootClass);
                     if (onDestroyMethod != null && onDestroyMethod.isConcrete()) {
                         if (!isWebViewCleanedUp(onDestroyMethod)) {
                             System.out.println("Potential Memory Leak: " + sootClass.getName() +
                                 " instantiates a WebView but may not clean it up properly in onDestroy().");
                         }
                     } else {
                         // onDestroy not found or not concrete, flag as potential leak
                         System.out.println("Potential Memory Leak: " + sootClass.getName() +
                             " instantiates a WebView but does not override onDestroy() for cleanup.");
                     }
                 }
             }
         }
     }

     private static SootMethod findOnDestroyMethod(SootClass sootClass) {
         for (SootMethod method : sootClass.getMethods()) {
             if (method.getName().equals("onDestroy")) {
                 return method;
             }
         }
         return null;
     }

     private static boolean isWebViewCleanedUp(SootMethod onDestroyMethod) {
         // Simplified check. In reality, you'd look for calls to WebView.destroy() or similar cleanup methods.
         Body body = onDestroyMethod.retrieveActiveBody();
         for (Unit unit : body.getUnits()) {
             if (unit instanceof InvokeStmt) {
                 InvokeStmt stmt = (InvokeStmt) unit;
                 if (stmt.getInvokeExpr().getMethod().getName().equals("destroy")) {
                     return true; // Found WebView.destroy() call
                 }
             }
         }
         return false;
     }
     
     // violation 7
     
     private static void analyzeLiveDataSingleEvents(SootClass sootClass) {
         if (!sootClass.isConcrete()) {
             return; // Skip abstract classes
         }

         for (SootMethod method : sootClass.getMethods()) {
             if (!method.isConcrete()) {
                 continue; // Skip non-concrete methods
             }

             Body body = method.retrieveActiveBody();

             // 1. Identify potential LiveData usage:
             Map<Local, SootClass> liveDataFields = findLiveDataFields(body); // Helper function (implementation below)

             // 2. Check for event-related method calls within the method:
             for (Unit unit : body.getUnits()) {
                 Stmt stmt = (Stmt) unit;
                 if (stmt instanceof InvokeStmt) {
                     InvokeExpr invokeExpr = ((InvokeStmt) stmt).getInvokeExpr();
                     String methodName = invokeExpr.getMethod().getName();
                     if (methodName.startsWith("show") || methodName.startsWith("navigate") ||
                         methodName.startsWith("dismiss")) { // Heuristic for event-related methods
                         for (Local local : liveDataFields.keySet()) {
                             if (stmt.getUseBoxes().contains(local)) { // Check if LiveData field is used in the statement
                                 System.out.println("Potential Caution 7 Violation in " + method.getSignature() +
                                                    ": Observing LiveData for a single event (like " + methodName + ") might lead to unexpected behavior. Consider using SingleLiveEvent or other mechanisms designed for handling single events.");
                             }
                         }
                     }
                 }
             }
         }
     }

     // Helper function to identify potential LiveData fields:
     private static Map<Local, SootClass> findLiveDataFields(Body body) {
    	    Map<Local, SootClass> liveDataFields = new HashMap<>();
    	    for (Unit unit : body.getUnits()) {
    	        Stmt stmt = (Stmt) unit;
    	        if (stmt instanceof AssignStmt) {
    	            AssignStmt assignStmt = (AssignStmt) stmt;
    	            Value leftOp = assignStmt.getLeftOp();
    	            Value rightOp = assignStmt.getRightOp();
    	            if (leftOp instanceof Local && rightOp instanceof NewExpr) {
    	                NewExpr newExpr = (NewExpr) rightOp;
    	                String typeName = newExpr.getBaseType().toString();
    	                if (typeName.equals("androidx.lifecycle.LiveData") ||
    	                    typeName.startsWith("androidx.lifecycle.MutableLiveData")) {
    	                    SootClass typeClass = Scene.v().getSootClass(typeName);
    	                    liveDataFields.put((Local) leftOp, typeClass);
    	                }
    	            }
    	        }
    	    }
    	    return liveDataFields;
    	}


     // violation 8
     private static void analyzeStaticContextUsage(SootClass sootClass) {
         // First, ensure the class is concrete to proceed with the analysis
         if (!sootClass.isConcrete()) return;

         // Iterate over all fields in the class to check for static Context or Activity references
         for (SootField field : sootClass.getFields()) {
             if (field.isStatic()) {
                 // Check if the field's type is a subtype of Context (including Activity)
                 if (isSubtypeOfContext(field.getType())) {
                     System.out.println("Potential Caution 8 Violation in " + sootClass.getName() +
                         ": Static field '" + field.getName() + "' may cause memory leaks by holding a context. " +
                         "Consider using Application context or weak references for contexts needed across the application lifecycle.");
                 }
             }
         }
     }

     // Helper method to check if a given Soot type is a subtype of Context
     private static boolean isSubtypeOfContext(Type fieldType) {
         if (!(fieldType instanceof RefType)) return false;
         SootClass fieldClass = ((RefType) fieldType).getSootClass();
         SootClass contextClass = Scene.v().getSootClass("android.content.Context");
         // Check if the field's class is a subclass of Context or the same as Context
         return Scene.v().getOrMakeFastHierarchy().isSubclass(fieldClass, contextClass) || fieldClass.equals(contextClass);
     }

     
     // violation 9
     
     private static void analyzeMethodForSQLiteLeaks(Body body) {
         Set<Local> openedDbLocals = new HashSet<>();
         Set<Local> closedDbLocals = new HashSet<>();

         // Identify open and close operations on SQLite database connections
         for (Unit unit : body.getUnits()) {
             Stmt stmt = (Stmt) unit;
             
             if (stmt.containsInvokeExpr()) {
                 InvokeExpr invokeExpr = stmt.getInvokeExpr();
                 SootMethod invokedMethod = invokeExpr.getMethod();
                 String methodName = invokedMethod.getName();

                 if (methodName.equals("openDatabase") || methodName.equals("getWritableDatabase") || methodName.equals("getReadableDatabase")) {
                     // If the database is opened, track the local variable
                     if (stmt instanceof AssignStmt) {
                         Local dbLocal = (Local) ((AssignStmt) stmt).getLeftOp();
                         openedDbLocals.add(dbLocal);
                     }
                 } else if (methodName.equals("close")) {
                     // If the database is closed, track the local variable
                     if (invokeExpr instanceof InstanceInvokeExpr) {
                         Local dbLocal = (Local) ((InstanceInvokeExpr) invokeExpr).getBase();
                         closedDbLocals.add(dbLocal);
                     }
                 }
             }
         }

         // Analyze for potential leaks: opened but not closed in the same method
         for (Local openedLocal : openedDbLocals) {
             if (!closedDbLocals.contains(openedLocal)) {
                 System.out.println("Potential Caution 9 Violation in " + body.getMethod().getSignature() + 
                         ": SQLite database connection opened but not properly closed, potentially leading to resource leaks.");
             }
         }
     }
       // violation 10
         
      private static void analyzeAdViewUsage(SootMethod method) {
             Body body = method.retrieveActiveBody();
             ExceptionalUnitGraph cfg = new ExceptionalUnitGraph(body);
             SimpleLocalDefs localDefs = new SimpleLocalDefs(cfg);

             CallGraph cg = Scene.v().getCallGraph();
             boolean adViewInitiated = false;
             boolean adViewDestroyed = false;

             // First pass: identify AdView creation within the method
             for (Unit unit : body.getUnits()) {
                 if (unit instanceof AssignStmt) {
                     AssignStmt assignStmt = (AssignStmt) unit;
                     if (assignStmt.getRightOp() instanceof NewExpr) {
                         NewExpr newExpr = (NewExpr) assignStmt.getRightOp();
                         if (newExpr.getType().toString().contains("com.google.android.gms.ads.AdView")) {
                             adViewInitiated = true;
                         }
                     }
                 }
             }

             // Second pass: inter-procedural analysis to check if AdView is destroyed properly
             if (adViewInitiated) {
                 Iterator<Edge> edgeIterator = cg.edgesOutOf(method);
                 while (edgeIterator.hasNext()) {
                     Edge edge = edgeIterator.next();
                     SootMethod tgt = edge.tgt();
                     if (tgt.getName().equals("onDestroy")) {
                         Body tgtBody = tgt.retrieveActiveBody();
                         for (Unit tgtUnit : tgtBody.getUnits()) {
                             if (tgtUnit.toString().contains("destroy")) {
                                 adViewDestroyed = true;
                                 break;
                             }
                         }
                     }
                 }

                 if (!adViewDestroyed) {
                     System.out.println("Potential Violation 10: AdView instance in " + method.getName() + " may not be properly destroyed, leading to a memory leak.");
                 }
             }
         }
         
        
 	

      private static boolean isSubclassOfLinearSnapHelper(SootClass sootClass) {
          // Implement logic to check if sootClass is a subclass of LinearSnapHelper
          // This is a simplified placeholder
          return sootClass.getSuperclass().getName().equals("androidx.recyclerview.widget.LinearSnapHelper");
      }
      
      private static void analyzeSnapHelperSubclass(SootClass snapHelperClass) {
          for (SootMethod method : snapHelperClass.getMethods()) {
              // 2. Look for overrides of critical methods
              if (method.getName().equals("calculateDistanceToFinalSnap") ||
                  method.getName().equals("findSnapView") ||
                  method.getName().equals("findTargetSnapPosition")) {
                  
            	  String redStart = "\u001B[31m";
                  String redEnd = "\u001B[0m";
                  
                  // This indicates potential custom snapping logic
            	  String sourceFileName = null;
	              	SourceFileTag sourceFileTag = (SourceFileTag) snapHelperClass.getTag("SourceFileTag");
	              	if (sourceFileTag != null) {
	              	    sourceFileName = sourceFileTag.getSourceFile();
	              	}
	              	
	              	
	              	
	              	System.out.println(redStart + "Potential Violation Detected: Custom SnapHelper Implementation" + redEnd);
	                System.out.println("Class: " + snapHelperClass.getName());
	                System.out.println("Source File: " + sourceFileName);
	                System.out.println("Issue: Subclass '" + snapHelperClass.getShortName() + "' customizes snapping behavior.");
	                System.out.println("Location: Subclass " + snapHelperClass.getName());
	                System.out.println("Code Snippet:");
	              	
	              	int linesPrinted = 0;
	              	
	              	Body methodBody = method.retrieveActiveBody();
                	
	              	for (Unit unit1 : methodBody.getUnits()) {
                	    if (linesPrinted >= 10) break; // Stop after printing 7 lines

                	    // Print the bytecode-level instruction, representing the logic rather than exact source code
                	    System.out.println("  " + unit1.toString());
                	    linesPrinted++;
                	}
	              	System.out.println("\n");
                  //System.out.println("Potential Violation 11: Custom snapping behavior in " + snapHelperClass.getName());
              }
          }
      }
      
      // violation 11.1
      
      private static void analyzeMethodForInsecureSSL(Body body, SootMethod method) {
          for (Unit stmt : body.getUnits()) {
              if (((Stmt) stmt).containsInvokeExpr() && ((Stmt) stmt).getInvokeExpr() instanceof InstanceInvokeExpr) {
                  InstanceInvokeExpr invokeExpr = (InstanceInvokeExpr) ((Stmt) stmt).getInvokeExpr();
                  String methodName = invokeExpr.getMethod().getName();

                  if (methodName.equals("init") && invokeExpr.getMethodRef().getDeclaringClass().getName().equals("javax.net.ssl.SSLContext")) {
                      // Detect SSLContext.init calls to check the TrustManager argument
                      if (isInsecureTrustManager(invokeExpr)) {
                          System.out.println("Potential Violation 11.1: Insecure SSL handling detected in method " + method.getSignature());
                      }
                  }
                  // Additional checks for HostnameVerifier can be added here
              }
          }
      }
      
      private static boolean isInsecureTrustManager(InstanceInvokeExpr invokeExpr) {
          // Placeholder for checking if the TrustManager argument to SSLContext.init is insecure.
          // This might involve analyzing the argument to detect instances that accept all certificates.
          return false; // Implement actual logic
      }
    
      // violation 14
      
      private static boolean callsSslErrorHandlerProceed(JimpleBody body) {
          for (Unit stmt : body.getUnits()) {
              if (((Stmt) stmt).containsInvokeExpr()) {
                  InvokeExpr invokeExpr = ((Stmt) stmt).getInvokeExpr();
                  if (invokeExpr instanceof InstanceInvokeExpr) {
                      InstanceInvokeExpr instanceInvokeExpr = (InstanceInvokeExpr) invokeExpr;
                      if (instanceInvokeExpr.getMethod().getName().equals("proceed") &&
                          instanceInvokeExpr.getBase().getType().toString().equals("android.webkit.SslErrorHandler")) {
                          return true;
                      }
                  }
              }
          }
          return false;
      }
      
      private static void performInterProceduralAnalysis(SootMethod onReceivedSslErrorMethod) {
          CallGraph cg = Scene.v().getCallGraph();
          Iterator<Edge> outEdges = cg.edgesOutOf(onReceivedSslErrorMethod);
          while (outEdges.hasNext()) {
              SootMethod targetMethod = (SootMethod) outEdges.next().tgt();
              if (targetMethod.isConcrete()) {
                  JimpleBody body = (JimpleBody) targetMethod.retrieveActiveBody();
                  if (callsSslErrorHandlerProceed(body)) {
                      System.out.println("Indirect violation found in " + targetMethod.getSignature());
                  }
              }
          }
      }
      
      // violation 15
      
      
      private static void detectPotentialInstanceCountViolations(SootClass sootClass) {
    	    String redStart = "\u001B[31m";
    	    String redEnd = "\u001B[0m";

    	    if (sootClass.isConcrete()) {
    	        for (SootField field : sootClass.getFields()) {
    	            if (field.isStatic()) {
    	                Type fieldType = field.getType();
    	                if (isPotentiallyLargeOrComplexType(fieldType)) {
    	                    System.out.println(redStart + "Potential InstanceCountViolation Risk Detected" + redEnd);
    	                    System.out.println("Class: " + sootClass.getName());
    	                    System.out.println("Issue: Static field '" + field.getName() + "' may lead to excessive memory usage.");
    	                    
//    	                    System.out.println("Recommendations:");
//    	                    System.out.println("- Reconsider the necessity of the static field.");
//    	                    System.out.println("- If possible, reduce the scope or convert to instance field.");
    	                    System.out.println();
    	                }
    	            }
    	        }

    	        for (SootMethod method : sootClass.getMethods()) {
    	            if (method.isConcrete()) {
    	                Body body = method.retrieveActiveBody();
    	                for (Unit unit : body.getUnits()) {
    	                    Stmt stmt = (Stmt) unit;
    	                    if (stmt.containsFieldRef() && stmt.getFieldRef() instanceof StaticFieldRef) {
    	                        StaticFieldRef staticFieldRef = (StaticFieldRef) stmt.getFieldRef();
    	                        SootField field = staticFieldRef.getField();
    	                        if (field.getDeclaringClass().equals(sootClass)) {
    	                            System.out.println(redStart + "Access to Static Field Detected" + redEnd);
    	                            System.out.println("Class: " + sootClass.getName());
    	                            System.out.println("Method: " + method.getSubSignature());
    	                            System.out.println("Access to static field: " + field.getName() + " may contribute to InstanceCountViolation.");
    	                            System.out.println("Location: " + unit);
    	                            System.out.println("Code Snippet:");
    	                            int linesPrinted = 0;
                                	for (Unit unit1 : body.getUnits()) {
                                	    if (linesPrinted >= 10) break; // Stop after printing 7 lines

                                	    // Print the bytecode-level instruction, representing the logic rather than exact source code
                                	    System.out.println("  " + unit1.toString());
                                	    linesPrinted++;
                                	}
                                	
//    	                            System.out.println("Recommendations:");
//    	                            System.out.println("- Review the necessity and usage of the static field within methods.");
//    	                            System.out.println("- Consider alternative designs that minimize static state.");
    	                            System.out.println();
    	                        }
    	                    }
    	                }
    	            }
    	        }
    	    }
    	}

      
      private static boolean isPotentiallyLargeOrComplexType(Type type) {
          // This is a simplistic check. In reality, you would check if the type is known to be large or complex (e.g., Bitmaps, large Collections, custom objects that aggregate many others, etc.)
          return true; // Placeholder for illustrative purposes
      }
      
      // violation 16
      
   // This approach cannot definitively detect violations but highlights potential issues.

      private static void analyzeUriBasedFileAccess(SootClass sootClass) {
    	    if (!sootClass.isConcrete()) {
    	        return; // Skip abstract classes
    	    }

    	    for (SootMethod method : sootClass.getMethods()) {
    	        if (!method.isConcrete()) {
    	            continue; // Skip non-concrete methods
    	        }

    	        Body body = method.retrieveActiveBody();
    	        
    	        List<Unit> relevantUnits = new ArrayList<>();
    	        
    	        // 1. Search for calls with potential URI arguments:
    	        boolean hasUriArgs = false;
    	        for (Unit unit : body.getUnits()) {
    	            Stmt stmt = (Stmt) unit;
    	            if (stmt instanceof InvokeStmt) {
    	                InvokeExpr invokeExpr = ((InvokeStmt) stmt).getInvokeExpr();
    	                for (Value arg : invokeExpr.getArgs()) {
    	                    // Check if the argument is a StringConstant before casting
    	                    if (arg instanceof StringConstant) {
    	                        StringConstant stringConst = (StringConstant) arg;
    	                        if (stringConst.value.startsWith("content://") || stringConst.value.startsWith("file://")) {
    	                            hasUriArgs = true;
    	                            relevantUnits.add(unit);
    	                            break; // Early exit if a potential URI argument is found
    	                        }
    	                    }
    	                }
    	                if (hasUriArgs) {
    	                    break; // Early exit from the loop over units if a potential URI argument is found
    	                }
    	            }
    	        }

    	        // 2. Reporting and recommendation:
    	        if (hasUriArgs) {
    	        	String redStart = "\u001B[31m";
    	            String redEnd = "\u001B[0m";
    	            String sourceFileName = getSourceFileName(sootClass); // Implement this method based on Soot API

    	            System.out.println(redStart + "Potential Violation Detected: URI-Based File Access" + redEnd);
    	            System.out.println("Class: " + sootClass.getName());
    	            System.out.println("Source File: " + sourceFileName);
    	            System.out.println("Method: " + method.getName());
    	            System.out.println("Relevant Code Snippet:");
    	            printRelevantCodeSnippets(relevantUnits, 7);
    	            
    	            System.out.println("Potential file access using URIs detected in " + method.getSignature() +
    	                    ". Be cautious of potential discrepancies in file handling behavior across different Android versions and devices. Ensure proper context-aware storage access mechanisms like ContextCompat.getExternalFilesDir() are used for reliable file access.");
    	        }
    	    }
    	}
      
      

    	// Mock-up method to print relevant code snippets from a list of Units
    	private static void printRelevantCodeSnippets(List<Unit> units, int limit) {
    	    int count = 0;
    	    for (Unit unit : units) {
    	        if (count >= limit) break;
    	        System.out.println(unit);
    	        count++;
    	    }
    	}

      
      // violation 17
      
      private static void analyzeNetworkOnMainThread(SootClass sootClass) {
    	    if (!sootClass.isConcrete()) {
    	        return; // Skip abstract classes
    	    }

    	    for (SootMethod method : sootClass.getMethods()) {
    	        if (!method.isConcrete()) {
    	            continue; // Skip non-concrete methods
    	        }

    	        Body body = method.retrieveActiveBody();

    	        // 1. Check for network calls:
    	        if (containsNetworkCalls(body)) {
    	            // 2. Check for potential main thread execution:
    	            if (mightRunOnMainThread(body)) {
    	                System.out.println("Potential NetworkOnMainThreadException in " + method.getSignature() +
    	                        ". Network calls are detected within a method that might be running on the main thread. Network tasks should be executed on a background thread.");
    	            }
    	        }
    	    }
    	}

    	private static boolean containsNetworkCalls(Body body) {
    	    for (Unit unit : body.getUnits()) {
    	        Stmt stmt = (Stmt) unit;
    	        if (stmt instanceof InvokeStmt) {
    	            InvokeExpr invokeExpr = ((InvokeStmt) stmt).getInvokeExpr();
    	            String className = invokeExpr.getMethodRef().getDeclaringClass().getName();
    	            if (className.startsWith("okhttp3") || className.startsWith("java.net.HttpURLConnection")) {
    	                return true;
    	            }
    	        }
    	    }
    	    return false;
    	}

    	private static boolean mightRunOnMainThread(Body body) {
    	    for (Unit unit : body.getUnits()) {
    	        Stmt stmt = (Stmt) unit;
    	        if (stmt instanceof InvokeStmt) {
    	            InvokeExpr invokeExpr = ((InvokeStmt) stmt).getInvokeExpr();
    	            String methodName = invokeExpr.getMethod().getName();
    	            String className = invokeExpr.getMethodRef().getDeclaringClass().getName();
    	            if ((methodName.equals("run") || methodName.equals("post") || methodName.equals("execute")) &&
    	                    (className.startsWith("android.os.Handler") || className.equals("android.os.AsyncTask"))) {
    	                return true;
    	            }
    	        }
    	    }
    	    return false;
    	}
    	
    	// violation 18
    	
    	// Starting Another AsyncTask from “doInBackground()” of the First AsyncTask Description: 
    	
    	private static void analyzeAsyncTaskNesting(SootClass sootClass) {
    	    if (!sootClass.isConcrete()) {
    	        return; // Skip abstract classes
    	    }

    	    for (SootMethod method : sootClass.getMethods()) {
    	        if (!method.isConcrete()) {
    	            continue; // Skip non-concrete methods
    	        }

    	        Body body = method.retrieveActiveBody();

    	        // 1. Identify potential AsyncTask subclasses (including custom implementations)
    	        if (isPotentialAsyncTaskSubclass(sootClass)) {
    	            for (Unit unit : body.getUnits()) {
    	                Stmt stmt = (Stmt) unit;
    	                if (stmt instanceof InvokeStmt) {
    	                    InvokeExpr invokeExpr = ((InvokeStmt) stmt).getInvokeExpr();
    	                    String methodName = invokeExpr.getMethod().getName();
    	                    String declaringClass = invokeExpr.getMethodRef().getDeclaringClass().getName();

    	                    // 2. Check for calls to constructor, execute(), or subclasses:
    	                    if ((methodName.equals("<init>") || methodName.equals("execute")) &&
    	                            (declaringClass.equals("android.os.AsyncTask") ||
    	                                    isPotentialAsyncTaskSubclass(invokeExpr.getMethodRef().getDeclaringClass()))) {
    	                        // 3. Ensure the call is not within a static context or constructor:
    	                        if (!isWithinStaticContext(body, unit) && !isWithinConstructor(body, unit)) {
    	                            System.out.println("Potential Violation 18 in " + method.getSignature() +
    	                                    ". Starting another AsyncTask from within doInBackground() is detected. This practice is discouraged due to potential race conditions, unexpected behavior, and performance issues. Consider creating and executing AsyncTasks on the UI thread or utilizing alternative asynchronous patterns.");
    	                        }
    	                    }
    	                }
    	            }
    	        }
    	    }
    	}

    	private static boolean isPotentialAsyncTaskSubclass(SootClass sootClass) {
    	    if (sootClass.getName().equals("android.os.AsyncTask")) {
    	        return true;
    	    }

    	    SootClass parentClass = sootClass.getSuperclass();
    	    return parentClass != null && isPotentialAsyncTaskSubclass(parentClass);
    	}

    	private static boolean isWithinStaticContext(Body body, Unit currentUnit) {
    	    boolean seenCurrentUnit = false;
    	    // Iterate through the units in the body
    	    for (Unit unit : body.getUnits()) {
    	        // If we've reached the current unit, stop the search
    	        if (unit == currentUnit) {
    	            seenCurrentUnit = true;
    	            break;
    	        }
    	        if (unit instanceof InvokeStmt) {
    	            InvokeExpr invokeExpr = ((InvokeStmt) unit).getInvokeExpr();
    	            if (invokeExpr instanceof StaticInvokeExpr) {
    	                return true; // Found a static method invocation before the current unit
    	            }
    	        }
    	    }
    	    return false; // No static method invocation found before the current unit
    	}

    	private static boolean isWithinConstructor(Body body, Unit currentUnit) {
    	    boolean found = false;
    	    // Iterate through the units in the body
    	    for (Unit unit : body.getUnits()) {
    	        // If we reach the current unit, stop the search
    	        if (unit == currentUnit) {
    	            break;
    	        }
    	        if (unit instanceof InvokeStmt) {
    	            InvokeExpr invokeExpr = ((InvokeStmt) unit).getInvokeExpr();
    	            if (invokeExpr instanceof SpecialInvokeExpr) {
    	                SootMethodRef methodRef = invokeExpr.getMethodRef();
    	                // Check if the method reference is a constructor
    	                if (methodRef.getName().equals("<init>")) {
    	                    found = true;
    	                }
    	            }
    	        }
    	    }
    	    return found;
    	}

    	
    	private static boolean isAsyncTaskSubclass(SootClass sootClass) {
            return sootClass.hasSuperclass() && sootClass.getSuperclass().getName().equals("android.os.AsyncTask");
        }

        private static void analyzeDoInBackgroundForAsyncTaskExecution(SootMethod doInBackgroundMethod) {
            if (!doInBackgroundMethod.isConcrete()) return;

            CallGraph cg = Scene.v().getCallGraph();
            Iterator<Edge> edges = cg.edgesOutOf(doInBackgroundMethod);
            while (edges.hasNext()) {
                SootMethod targetMethod = edges.next().tgt();
                if (targetMethod.getName().equals("execute") && isAsyncTaskSubclass(targetMethod.getDeclaringClass())) {
                    System.out.println("Violation found: AsyncTask executed from doInBackground in " + doInBackgroundMethod);
                }
            }
        }

      
        // violatio 19
        
        private static void analyzePotentialStorageAccess(SootClass sootClass) {
        	//System.out.println("coming");
            if (!sootClass.isConcrete()) {
                return; // Skip abstract classes
            }

            for (SootMethod method : sootClass.getMethods()) {
                if (!method.isConcrete()) {
                    continue; // Skip non-concrete methods
                }

                Body body = method.retrieveActiveBody();

                // 1. Search for calls to common storage access methods:
                boolean hasStorageAccessCalls = false;
                for (Unit unit : body.getUnits()) {
                    Stmt stmt = (Stmt) unit;
                    if (stmt instanceof InvokeStmt) {
                        InvokeExpr invokeExpr = ((InvokeStmt) stmt).getInvokeExpr();
                        String className = invokeExpr.getMethodRef().getDeclaringClass().getName();
                        String methodName = invokeExpr.getMethod().getName();
                        if ((className.startsWith("java.io.File") || className.startsWith("android.os.Environment")) &&
                                (methodName.equals("exists") || methodName.equals("list") || methodName.startsWith("get") || methodName.startsWith("open"))) {
                            hasStorageAccessCalls = true;
                            break; // Early exit if potential storage access is found
                        }
                    }
                }

                // 2. Reporting and recommendation:
                if (hasStorageAccessCalls) {
                    System.out.println("Potential storage access detected in " + method.getSignature() +
                            ". While Soot analysis cannot directly verify permission handling, ensure proper permission checks (e.g., ContextCompat.checkSelfPermission()) are implemented before accessing external storage locations. Requesting necessary permissions at runtime is crucial for secure storage access.");
                }
            }
        }
        
        // violation 20
        
        
        private static void analyzePotentialANR(SootClass sootClass) {
            if (!sootClass.isConcrete()) {
                return; // Skip abstract classes
            }

            for (SootMethod method : sootClass.getMethods()) {
                if (!method.isConcrete()) {
                    continue; // Skip non-concrete methods
                }

                Body body = method.retrieveActiveBody();
                
                List<Unit> relevantUnitsForBlockingCalls = new ArrayList<>(); 
                
                // 1. Search for calls to blocking methods:
                boolean hasBlockingCalls = false;
                for (Unit unit : body.getUnits()) {
                	
                    Stmt stmt = (Stmt) unit;
                    if (stmt instanceof InvokeStmt) {
                        InvokeExpr invokeExpr = ((InvokeStmt) stmt).getInvokeExpr();
                        String className = invokeExpr.getMethodRef().getDeclaringClass().getName();
                        String methodName = invokeExpr.getMethod().getName();
                        
                        // Focus on common blocking operations:
                        if ((className.startsWith("java.io") &&
                                (methodName.equals("sleep") || methodName.equals("wait") || methodName.startsWith("read"))) ||
                                (className.startsWith("java.net") &&
                                        (methodName.equals("connect") || methodName.equals("read") || methodName.equals("write")))) {
                            hasBlockingCalls = true;
                            
                            break; // Early exit if potential blocking calls are found
                        }
                    }
                }

                // 2. Search for long-running loops:
                int loopCount = 0;
                for (Unit unit : body.getUnits()) {
                    if (unit instanceof GotoStmt || unit instanceof IfStmt) {
                    	if(loopCount < 1000000) {
                    		relevantUnitsForBlockingCalls.add(unit);
                    	}
                    	
                        loopCount++; // Count potential loop iterations (heuristic)
                    }
                }

                // 3. Reporting and recommendation:
                //
                if (hasBlockingCalls || loopCount > 100000000) {
                	
                	printANRWarning(sootClass, method, relevantUnitsForBlockingCalls, loopCount);
                }
            }
        }
        
        private static void printANRWarning(SootClass sootClass, SootMethod method, List<Unit> blockingUnits, int loopCount) {
            String redStart = "\u001B[31m";
            String redEnd = "\u001B[0m";
            // Attempt to get the source file name, if possible
            String sourceFileName = getSourceFileName(sootClass); // Implement this based on available Soot API

            System.out.println(redStart + "Potential ANR Detected" + redEnd);
            System.out.println("Class: " + sootClass.getName());
            System.out.println("Method: " + method.getSignature());
            if (sourceFileName != null) {
                System.out.println("Source File: " + sourceFileName);
            }
            System.out.println("Issue: Potential blocking operations or long-running loops detected.");
            System.out.println("Relevant Code Snippet:");
            blockingUnits.forEach(unit -> System.out.println("  " + unit.toString()));
            if (loopCount > 1000) {
                System.out.println("  ...potential long-running loop detected...");
            }
            System.out.println("Recommendations:");
            System.out.println("- Consider performing blocking operations on a background thread.");
            System.out.println("- Utilize asynchronous mechanisms to maintain UI responsiveness.");
            System.out.println();
        }
        
        // violation 23
        
        // static analysis and Intra-Procedural Analysis (it analyzes method calls across different classes, tracing potential memory leaks that span across inner class boundaries within the outer class context.)
        // 
        private static void analyzePotentialMemoryLeaksDueToHandlers(SootClass sootClass) {
            // Iterate over all classes to find inner classes of the current class
            String outerClassName = sootClass.getName();
            for (SootClass potentialInnerClass : Scene.v().getApplicationClasses()) {
                if (potentialInnerClass.getName().startsWith(outerClassName + "$") && !potentialInnerClass.isStatic()) {
                    // Found a non-static inner class
                    for (SootMethod method : potentialInnerClass.getMethods()) {
                        if (method.isConcrete()) {
                            Body body = method.retrieveActiveBody();
                            for (Unit unit : body.getUnits()) {
                                Stmt stmt = (Stmt) unit;
                                if (stmt instanceof InvokeStmt) {
                                    InvokeExpr invokeExpr = ((InvokeStmt) stmt).getInvokeExpr();
                                    SootMethodRef methodRef = invokeExpr.getMethodRef();
                                    if (methodRef.getSignature().contains("android.os.Handler") &&
                                        (methodRef.getName().equals("post") || methodRef.getName().equals("sendMessage"))) {
                                        
                                    	String sourceFileName = null;
                                    	SourceFileTag sourceFileTag = (SourceFileTag) sootClass.getTag("SourceFileTag");
                                    	if (sourceFileTag != null) {
                                    	    sourceFileName = sourceFileTag.getSourceFile();
                                    	}
                                    	
                                    	String redStart = "\u001B[31m";
                                    	String redEnd = "\u001B[0m";
                                    	

                                    	// Enhanced violation output with limited code snippet lines
                                    	System.out.println(redStart + "Potential Memory Leak Detected" + redEnd);
                                    	System.out.println("Class: " + potentialInnerClass.getName());
                                    	if(sourceFileName != null) {
                                    		System.out.println("Source File: " + sourceFileName);
                                    	}
                                    	
                                    	System.out.println("Issue: Non-static inner class '" + potentialInnerClass.getShortName() + "' may hold an implicit reference to the outer class, hindering garbage collection.");
                                    	System.out.println("Location: Method " + method.getSubSignature() + " in class " + potentialInnerClass.getName());
                                    	System.out.println("Code Snippet:");

                                    	int linesPrinted = 0;
                                    	for (Unit unit1 : body.getUnits()) {
                                    	    if (linesPrinted >= 10) break; // Stop after printing 7 lines

                                    	    // Print the bytecode-level instruction, representing the logic rather than exact source code
                                    	    System.out.println("  " + unit1.toString());
                                    	    linesPrinted++;
                                    	}

                                    	System.out.println("Recommendations:");
                                    	System.out.println("- Consider making '" + potentialInnerClass.getShortName() + "' a static inner class.");
                                    	System.out.println("- Use a static inner class or a separate class to avoid implicit references to the outer class.");
                                    	System.out.println();

                                    	
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // violation 22
        
        private static void analyzePotentialDeadlocks(SootClass sootClass) {
            for (SootMethod method : sootClass.getMethods()) {
                if (method.isConcrete()) { // Focus on concrete methods
                    Body body = method.retrieveActiveBody();

                    boolean withinSynchronizedBlock = false;
                    for (Unit unit : body.getUnits()) {
                        // Monitor enter marks the start of a synchronized block
                        if (unit instanceof MonitorStmt && ((MonitorStmt) unit).getOp() instanceof EnterMonitorStmt) {
                            withinSynchronizedBlock = true;
                        }

                        // Analyze accesses within the synchronized block
                        if (withinSynchronizedBlock) {
                            // Example: detect field accesses or method invocations
                            if (unit instanceof InvokeStmt || unit instanceof AssignStmt) {
                                // Simplified example to identify field accesses or method invocations
                                System.out.println("Potential synchronization or access within synchronized block detected in " + method.getSignature());
                            }
                        }

                        // Monitor exit marks the end of a synchronized block
                        if (unit instanceof MonitorStmt && ((MonitorStmt) unit).getOp() instanceof ExitMonitorStmt) {
                            withinSynchronizedBlock = false;
                        }
                    }
                }
            }
        }



        // violation 21
        
        private static void analyzeMethodForHttpUsage(Body body) {
            Chain<Unit> units = body.getUnits();
            for (Unit unit : units) {
                if (unit instanceof Stmt) {
                    Stmt stmt = (Stmt) unit;
                    if (stmt.containsInvokeExpr()) {
                        InvokeExpr invokeExpr = stmt.getInvokeExpr();
                        if (invokeExpr.getMethod().getName().equals("openConnection") ||
                            invokeExpr.getMethod().getName().contains("execute")) { // Assuming methods that might involve network requests
                            for (Object arg : invokeExpr.getArgs()) {
                                if (arg instanceof StringConstant) {
                                    StringConstant url = (StringConstant) arg;
                                    if (url.value.startsWith("http://")) {
                                        System.out.println("Potential security violation found in " + body.getMethod() +
                                                ". HTTP URL used: " + url.value);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        
        public static void analyzeAppForHttpUsage() {
            for (SootClass sootClass : Scene.v().getApplicationClasses()) {
                for (SootMethod method : sootClass.getMethods()) {
                    if (method.isConcrete()) {
                        Body body = method.retrieveActiveBody();
                        analyzeMethodForHttpUsage(body);
                    }
                }
            }
        }
        

        // violation 24
        
        private static void analyzeMethodForSensitiveLogs(Body body) {
        	SootMethod method = body.getMethod();
        	String sourceFileName = null;
            SourceFileTag sourceFileTag = (SourceFileTag) method.getDeclaringClass().getTag("SourceFileTag");
            if (sourceFileTag != null) {
                sourceFileName = sourceFileTag.getSourceFile();
            }
            for (Unit unit : body.getUnits()) {
                Stmt stmt = (Stmt) unit;
                if (stmt.containsInvokeExpr()) {
                    InvokeExpr invokeExpr = stmt.getInvokeExpr();
                    if (invokeExpr.getMethod().getDeclaringClass().getName().equals("android.util.Log")) {
                        List<String> sensitiveKeywords = Arrays.asList("password", "token", "apikey");
                        boolean isSensitive = false;

                        // Check arguments for sensitive keywords
                        for (Object arg : invokeExpr.getArgs()) {
                            String argStr = arg.toString().toLowerCase();
                            for (String keyword : sensitiveKeywords) {
                                if (argStr.contains(keyword)) {
                                    isSensitive = true;
                                    break;
                                }
                            }
                            if (isSensitive) {
                                break;
                            }
                        }

                        if (isSensitive) {
                        	String redStart = "\u001B[31m";
                            String redEnd = "\u001B[0m";

                            System.out.println(redStart + "Potential Sensitive Log Violation Detected" + redEnd);
                            System.out.println("Class: " + method.getDeclaringClass().getName());
                            if (sourceFileName != null) {
                                System.out.println("Source File: " + sourceFileName);
                            }

                            System.out.println("Issue: Sensitive information logged.");
                            System.out.println("Location: Method " + method.getSignature());
                            System.out.println("Code Snippet:");
                            printCodeSnippet(body, unit); // Assuming a method printCodeSnippet is defined to print the Jimple code around the unit

                            System.out.println("Recommendations:");
                            System.out.println("- Avoid logging sensitive information.");
                            System.out.println("- Use more secure ways to handle sensitive data.");
                            System.out.println();
                            //System.out.println("Potential Violation 24: Sensitive information might be logged at " + stmt + " in method " + body.getMethod());
                        }
                    }
                }
            }
        }
        
        //violation 25
        
        private static final Pattern sensitiveDataPattern = Pattern.compile(".*(key|token|password|secret|credential).*", Pattern.CASE_INSENSITIVE);
        
        
        private static void analyzeMethodForViolations(SootMethod method) {
            Body body = method.retrieveActiveBody();
            
            String sourceFileName = "Unknown";
            SourceFileTag sourceFileTag = (SourceFileTag) method.getDeclaringClass().getTag("SourceFileTag");
            if (sourceFileTag != null) {
                sourceFileName = sourceFileTag.getSourceFile();
            }
            
            for (Unit unit : body.getUnits()) {
                Stmt stmt = (Stmt) unit;
               
                
                // Violation 25: Check for hardcoded sensitive data
                if (stmt instanceof AssignStmt) {
                    Value rightOp = ((AssignStmt) stmt).getRightOp();
                    if (rightOp instanceof StringConstant) {
                        String stringValue = ((StringConstant) rightOp).value;
                        if (sensitiveDataPattern.matcher(stringValue).find()) {
                        	 String redStart = "\u001B[31m";
                        	 String redEnd = "\u001B[0m";
                        	    
                        	System.out.println(redStart + "Potential Hardcoded sensitive information Violation  Detected" + redEnd);
                            System.out.println("Class: " + method.getDeclaringClass().getName());
                           
                            System.out.println("Source File: " + sourceFileName);
                         
                            
                            System.out.println("Issue: Hardcoded sensitive information found.");
                            System.out.println("Location: Method " + method.getSubSignature() + " in class " + method.getDeclaringClass().getName());
                            System.out.println("Code Snippet:");
                            printCodeSnippet(body, unit);
                            System.out.println("Recommendations:");
                            System.out.println("- Avoid hardcoding sensitive information in your code.");
                            System.out.println("- Consider using more secure mechanisms, such as storing secrets in environment variables or secure storage.");
                            System.out.println();
                        }
                    }
                }
            }
        }
        
        private static void printCodeSnippet(Body body, Unit highlightUnit) {
            int linesPrinted = 0;
            for (Unit unit : body.getUnits()) {
                if (linesPrinted >= 7) break; // Limit the number of printed lines for brevity

                if (unit.equals(highlightUnit)) {
                    // Highlight the specific unit where the violation was found
                    System.out.println("  >> " + unit.toString());
                } else {
                    System.out.println("  " + unit.toString());
                }
                linesPrinted++;
            }
        }
        
        // violation 26
        private static void analyzeMethodForLayoutInflaterUsage(SootMethod method) {
            Body body = method.retrieveActiveBody();
            
            for (Unit unit : body.getUnits()) {
                Stmt stmt = (Stmt) unit;
                
                // Check for LayoutInflater instantiation
                if (stmt.containsInvokeExpr()) {
                    InvokeExpr invokeExpr = stmt.getInvokeExpr();
                    
                    if (invokeExpr instanceof StaticInvokeExpr) {
                        SootMethod invokedMethod = invokeExpr.getMethod();
                        if (invokedMethod.getSignature().contains("android.view.LayoutInflater from(")) {
                            // Found LayoutInflater.from() usage
                            // Additional checks to refine detection can be implemented here
                            
                            // Report potential violation
                            System.out.println("Potential Violation 26 detected in " + method.getSignature());
                        }
                    }
                }
            }
        }
        
        
        
    


    private static boolean checkExplicitIntent(String intentType) {
        return "android.content.Intent".equals(intentType);
    }
}
    