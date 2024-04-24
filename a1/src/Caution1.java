
import soot.*;
import soot.jimple.*;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.options.Options;
import soot.toolkits.scalar.Pair;

import java.io.File;
import java.util.*;

public class Caution1 {

	public static String sourceDirectory = System.getProperty("user.dir") + File.separator + "Test";
	public static String circleClassName = "ExplicitIntentExample";

	// ImplicitIntentExample
	// ExplicitIntentExample

	public static void setupSoot() {
		
	}

	public static void main(String[] args) {
		// setting the soot with various options
		
		G.reset();
		Options.v().set_prepend_classpath(true);
		Options.v().set_allow_phantom_refs(true);
		System.out.println(sourceDirectory);
		String javapath = System.getProperty("java.class.path");
		String jredir = System.getProperty("java.home") + "/lib/rt.jar";
		String path = javapath + File.pathSeparator + jredir;
		Options.v().set_soot_classpath(path);
		Options.v().set_output_format(Options.output_format_jimple);
		Options.v().set_process_dir(Collections.singletonList(sourceDirectory));
		Scene.v().loadNecessaryClasses();
		PackManager.v().runPacks();
		
		SootClass circleClass = reportSootClassInfo();
		System.out.println("------------" + circleClass);

		SootMethod areaMethod = reportSootMethodInfo(circleClass);
		System.out.println("****** Class Body ******");
		JimpleBody body = (JimpleBody) areaMethod.getActiveBody();
		reportLocalInfo(body);
		int c = 0;

		System.out.println("----------------");
		boolean intentFound = false;

		for (Unit u : body.getUnits()) {
			c++;
			Stmt stmt = (Stmt) u;
			System.out.println(String.format("(%d): %s", c, stmt));
			if (stmt.toString().matches("()$")) {
				intentFound = true;

			}

		}
		if (!intentFound) {
			System.out.println("****************************\n" + "RESULT::Class contains Explicit Intent\n"
					+ "*****************************************");
		} else {
			System.out.println("*********************************\n" + "RESULT::Class contains Implicit Intent\n"
					+ "******************************************");
		}

		SootField radiusField = reportSootFieldInfo(circleClass);

	}

	private static void reportLocalInfo(JimpleBody body) {
		System.out.println(String.format("Local variables count: %d", body.getLocalCount()));
		Local thisLocal = body.getThisLocal();
		Type thisType = thisLocal.getType();
		// Local paramLocal = body.getParameterLocal(0);
	}

//
	private static SootMethod reportSootMethodInfo(SootClass circleClass) {
		System.out.println("***** Class Methods ************");
		System.out.println(String.format("List of class %s's methods:", circleClass.getName()));
		for (SootMethod sootMethod : circleClass.getMethods())
			System.out.println(String.format("- %s", sootMethod.getName()));

		SootMethod constructorMethod = circleClass.getMethodByName("<init>");
		System.out.println(String.format("Test : %s", constructorMethod.getName()));
		System.out.println(String.format("Method Signature: %s", constructorMethod.getSignature()));
		System.out.println(String.format("Method Subsignature: %s", constructorMethod.getSubSignature()));
		System.out.println(String.format("Method Name: %s", constructorMethod.getName()));
		System.out.println(String.format("Declaring class: %s", constructorMethod.getDeclaringClass()));
		try {
			SootMethod helloMethod = circleClass.getMethodByName("hello");
		} catch (Exception exception) {
			System.out.println("Th method 'area' is overloaded and Soot cannot retrieve it by name");
		}
		return circleClass.getMethod("void <init>()");
	}

//
	private static SootField reportSootFieldInfo(SootClass circleClass) {
		for (SootField sootField : circleClass.getFields()) {
			System.out.println(sootField.getName() + " , " + sootField.getDeclaration() + " , " + sootField.toString()
					+ " , " + sootField.getSignature());

		}
		SootField intentField = circleClass.getFieldByName("a");

		System.out.println(String.format("Field is %s", intentField));
		return intentField;
	}

//
	private static SootClass reportSootClassInfo() {
		System.out.println("-----Class-----");
		SootClass circleClass = Scene.v().getSootClass(circleClassName);
		System.out.println(String.format("The class %s is an %s class, loaded with %d methods! ", circleClass.getName(),
				circleClass.isApplicationClass() ? "Application" : "Library", circleClass.getMethodCount()));
		String wrongClassName = "Circrle";
		SootClass notExistedClass = Scene.v().getSootClassUnsafe(wrongClassName, false);
		System.out.println(
				String.format("getClassUnsafe: Is the class %s null? %b", wrongClassName, notExistedClass == null));
		try {
			notExistedClass = Scene.v().getSootClass(wrongClassName);
			System.out.println(String.format("getClass creates a phantom class for %s: %b", wrongClassName,
					notExistedClass.isPhantom()));
		} catch (Exception exception) {
			System.out.println(String.format("getClass throws an exception for class %s.", wrongClassName));
		}
		Type circleType = circleClass.getType();
		System.out.println(String.format("Class '%s' is same as class of type '%s': %b", circleClassName,
				circleType.toString(), circleClass.equals(Scene.v().getSootClass(circleType.toString()))));
		return circleClass;
	}
	
	
}