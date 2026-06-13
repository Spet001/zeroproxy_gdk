using System;
using System.Reflection;
using System.IO;

class Program {
    static void Main() {
        string[] winmds = Directory.GetFiles(@"C:\Windows\System32\WinMetadata", "*.winmd");
        foreach (var winmd in winmds) {
            try {
                Assembly asm = Assembly.ReflectionOnlyLoadFrom(winmd);
                Type[] types;
                try {
                    types = asm.GetTypes();
                } catch (ReflectionTypeLoadException ex) {
                    types = ex.Types;
                }
                if (types == null) continue;
                foreach (Type t in types) {
                    if (t != null && (t.FullName.Contains("StoreContextServer") || t.FullName.Contains("StoreContext"))) {
                        Console.WriteLine("Type: " + t.FullName);
                        foreach (MethodInfo m in t.GetMethods()) {
                            Console.WriteLine("  Method: " + m.Name);
                            foreach (ParameterInfo p in m.GetParameters()) {
                                Console.WriteLine("    Param: " + p.ParameterType.Name + " " + p.Name);
                            }
                            Console.WriteLine("    Returns: " + m.ReturnType.Name);
                        }
                    }
                }
            } catch { }
        }
    }
}
