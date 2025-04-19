import bisa, claripy

# Подгрузка файла
project = bisa.Project('./binary_with_constraints', auto_load_libs=False)


start_addr = project.loader.main_object.get_symbol("start_func")
result_addr = project.loader.main_object.get_symbol("win")

input_arg = claripy.BVS('input_arg', 32)

# Создание нового состояния 
init_state = project.factory.blank_state(addr=start_addr.rebased_addr)

init_state.regs.edi = input_arg

# Работа с симуляцией
simulation = project.factory.simulation_manager(init_state)

# Результат, которого надо достичь
simulation.explore(find=result_addr.rebased_addr)

# Проверка, нашли ли мы состояние
if simulation.found:
    input_value = simulation.found[0].solver.eval(input_arg)
    print(f"Подходящее значение: {input_value}")

    constraints = simulation.found[0].solver.constraints

    solver = claripy.Solver()
    solver.add(constraints)
    min_val = solver.min(input_arg)
    max_val = solver.max(input_arg)
    print(f"Минимальные и максимальные значения: {min_val} {max_val}")
else:
    print("Значения найти не получилось")
