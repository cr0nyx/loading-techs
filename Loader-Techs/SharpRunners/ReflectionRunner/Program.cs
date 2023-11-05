using System.Reflection;

namespace ReflectionRunner
{
    internal class Program
    {
        static void Main(string[] args)
        {
            byte[] data = { 0x00 }; // place for your .NET binary

            Assembly assembly = Assembly.Load(data);
            var type = assembly.GetType("AssemblyClassName");
            var method = type.GetMethod("AssemblyMethodName");
            method.Invoke(assembly, new object[] { null });
        }
    }
}
