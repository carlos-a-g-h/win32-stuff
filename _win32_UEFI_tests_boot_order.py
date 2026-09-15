#!/usr/bin/python3

# DONE

from win32_UEFI import (

	env_gain_aditional_privileges,

	import_GetFwEnVarW,

	gen_str_BootNNNN,

	get_evar_BootOrder,

	build_efi_BootOrder,

	parse_efi_BootOrder,
)

# Gain elevated privileges

env_gain_aditional_privileges()

# Import the necessary function

GetFwEnVarW=import_GetFwEnVarW()

# Get the current boot order as a list

boot_order=get_evar_BootOrder(GetFwEnVarW,as_list=True)

print("BootOrder:",boot_order)

# Generate a boot entry name that doesn't exist yet

boot_entry_new=gen_str_BootNNNN(boot_order)

print("New boot entry:",boot_entry_new)

# Append the new boot entry name to the boot order list (it will be placed at the end)

boot_order.append(boot_entry_new)

# Serialize the new boot order

boot_order_enc=build_efi_BootOrder(boot_order)

print("encoded boot order:",boot_order_enc)

# Deserialize the new boot order

boot_order_ok=parse_efi_BootOrder(boot_order_enc)

print("deserialized boot order:",boot_order_ok)
