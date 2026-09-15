#!/usr/bin/python3

from win32_UEFI import (

	init_gain_aditional_privileges,
	import_GetFwEnVarW,
	hl_get_efi_BootOrder,

	build_efi_BootOrder,
	parse_efi_BootOrder,
)

init_gain_aditional_privileges()

GetFwEnVarW=import_GetFwEnVarW()

# test 1 (passed)
# Pull out the current BootOrder

boot_order=hl_get_efi_BootOrder(GetFwEnVarW,as_list=True)

print("BootOrder:",boot_order)

# test 2 (passed)
# Append a new Boot entry

boot_order.append("BootFFFF")

boot_order_enc=build_efi_BootOrder(boot_order)

print(
	"New boot order proposal:",
	parse_efi_BootOrder(
		boot_order_enc
	)
)
