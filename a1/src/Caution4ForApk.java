import soot.*;
import soot.jimple.*;
import soot.options.Options;

import java.io.File;
import java.util.Collections;
import java.util.Iterator;


public class Caution4ForApk {
	
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

                    for (Unit unit : body.getUnits()) {
                        Stmt stmt = (Stmt) unit;

                        if (stmt.containsInvokeExpr()) {
                            InvokeExpr invokeExpr = stmt.getInvokeExpr();
                            SootMethod calledMethod = invokeExpr.getMethod();
                            String methodName = calledMethod.getName();
                            SootClass declaringClass = calledMethod.getDeclaringClass();

                            if (("startService".equals(methodName) || "bindService".equals(methodName))
                                    && "android.content.Context".equals(declaringClass.getName())) {
                                Type intentType = calledMethod.getParameterType(0);
                                if (intentType instanceof RefType && "android.content.Intent".equals(intentType.toString())) {
                                    Value intentValue = invokeExpr.getArg(0);
                                    if (intentValue instanceof Local) {
                                        boolean explicitIntentFound = false;
                                        Iterator<Unit> defIt = body.getUnits().iterator();
                                        while (defIt.hasNext() && !explicitIntentFound) {
                                            Stmt defStmt = (Stmt) defIt.next();
                                            if (defStmt instanceof DefinitionStmt) {
                                                DefinitionStmt definitionStmt = (DefinitionStmt) defStmt;
                                                if (definitionStmt.getLeftOp().equivTo(intentValue)
                                                        && definitionStmt.getRightOp() instanceof NewExpr) {
                                                    explicitIntentFound = true;
                                                }
                                            }
                                        }
                                        if (!explicitIntentFound) {
                                            System.out.println("Warning: Implicit Intent found at " + stmt + " in method " + method);
                                            System.out.println("Suggestion: Always use an explicit intent when starting a service.");
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}