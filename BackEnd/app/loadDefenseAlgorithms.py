import os
import importlib.util
import multiprocessing

# Ruta donde se encuentran los algoritmos de defensa
defenseAlgorithmsPath = "./app/defenseAlgorithms"

# Diccionario donde almacenamos los módulos y la lista de nombres
algorithms = {} # Clave->Nombre, Valor->Modulo

def getDefenseAlgorithmNames():
    return list(algorithms.keys())


def loadDefenseAlgorithms(path=defenseAlgorithmsPath):
    
    if __name__ == '__main__':

        # print("Cargando algoritmos de defensa...")
        global algorithm_names
        algorithms.clear()

        for fileName in os.listdir(path):
            if fileName.endswith(".py"):  # Solo archivos .py
                moduleName = fileName[:-3]  # Nombre del módulo sin extensión
                modulePath = os.path.join(path, fileName)
                spec = importlib.util.spec_from_file_location(moduleName, modulePath)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

                if hasattr(module, "detect"):
                    algorithms[moduleName] = module
                    # print(f"✅ {fileName} cargado correctamente.")
                    moduleProcess = multiprocessing.Process(target=module.detect, daemon=True)
                    moduleProcess.start()
                else:
                    print(f"⚠️ {fileName} no contiene una función `detect`.")

def startModule(algorithm_name):
    if algorithm_name in algorithms:
        module = algorithms[algorithm_name]
        if module.running:
            print(f"❕ El módulo {algorithm_name} ya está en ejecución.")
            return "Start completado."
        module.running = True
    else:
        print(f"❗️ El módulo {algorithm_name} no está cargado. ¿El .py sigue la especificación?.")
        return "Stop módulo no cargado."


def stopModule(algorithm_name):
    if algorithm_name in algorithms:
        module = algorithms[algorithm_name]
        if not module.running:
            print(f"❕ El módulo {algorithm_name} no estaba en ejecución.")
            return "Stop completado."
        module.running = False
    else:
        print(f"❗️ El módulo {algorithm_name} no está cargado. ¿El .py sigue la especificación?.")
        return "Stop módulo no cargado."
