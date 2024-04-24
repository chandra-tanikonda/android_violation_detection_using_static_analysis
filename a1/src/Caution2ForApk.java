import soot.*;
import soot.jimple.*;
import soot.options.Options;

import java.io.File;
import java.util.*;

public class Caution2ForApk {
	
	private final static String USER_HOME = System.getProperty("user.home");
    private static String androidJar = USER_HOME + "/Library/Android/sdk/platforms";
    static String androidDemoPath = System.getProperty("user.dir") + File.separator + "Demo" + File.separator + "Android";
    static String apkPath = androidDemoPath + File.separator + "/basic_financial_application.apk";
    static String outputPath = androidDemoPath + File.separator + "/Instrumented";
    
    public static void main(String[] args) {

        Options.v().set_src_prec(Options.src_prec_apk);
        Options.v().set_process_dir(Collections.singletonList(apkPath));
        Options.v().set_android_jars(androidJar);
        Options.v().set_allow_phantom_refs(true);
        Options.v().set_whole_program(true);
        Options.v().set_process_multiple_dex(true);

        Scene.v().loadNecessaryClasses();
        analyze();
    }
    
    private static void analyze() {
        for (SootClass sootClass : Scene.v().getApplicationClasses()) {
            for (SootMethod method : sootClass.getMethods()) {
                if (method.isConcrete()) {
                    Body body = method.retrieveActiveBody();
                    HashMap<Value, Integer> intentFlags = new HashMap<>();

                    for (Unit unit : body.getUnits()) {
                        Stmt stmt = (Stmt) unit;

                        if (stmt.containsInvokeExpr()) {
                            InvokeExpr invokeExpr = stmt.getInvokeExpr();
                            String methodName = invokeExpr.getMethod().getName();
                            Value base = null;

                            if (invokeExpr instanceof InstanceInvokeExpr) {
                                base = ((InstanceInvokeExpr) invokeExpr).getBase();
                            }

                            if ("setData".equals(methodName) || "setType".equals(methodName)) {
                                int flag = "setData".equals(methodName) ? 1 : 2;

                                if (intentFlags.containsKey(base)) {
                                    int existingFlag = intentFlags.get(base);
                                    if ((existingFlag & flag) == 0) {
                                        intentFlags.put(base, existingFlag | flag);
                                    }
                                } else {
                                    intentFlags.put(base, flag);
                                }
                            } else if ("setDataAndType".equals(methodName)) {
                                intentFlags.remove(base);
                            }
                        }
                    }

                    for (Map.Entry<Value, Integer> entry : intentFlags.entrySet()) {
                        if (entry.getValue() == 3) {
                            System.out.println("Warning: Found both setData() and setType() called on the same Intent object in method " + method);
                            System.out.println("Suggestion: Use setDataAndType() instead to set both URI and MIME type.");
                        }
                    }
                }
            }
        }
    }
}