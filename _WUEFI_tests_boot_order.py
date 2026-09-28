#!/usr/bin/python3

# DONE

from WPrivilege import env_gain_extra_priv

from WUEFI import get_evar_BootOrder

from WUEFI_ctypes import import_GetFwEnVarW

from WUEFI_utils import gen_str_BootNNNN

from WUEFI_serde import (
	build_efi_BootOrder,
	parse_efi_BootOrder
)

# Gain elevated privileges

env_gain_extra_priv()

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
