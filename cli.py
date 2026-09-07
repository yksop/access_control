"""Interactive text menus for the access control system."""

from datetime import datetime, timedelta

import config


def access_interface(system):
    while True:
        print("\n=== ACCESS ===")
        print("1. Generate access QR")
        print("2. Back to main menu")
        choice = input("Choose option (1-2): ").strip()

        if choice == "1":
            user_id = input("Enter User ID: ").strip()
            pin_code = input("Enter PIN: ").strip()
            success, qr_file = system.authenticate_and_generate_qr(user_id, pin_code)
            if success:
                print(f"QR code ready: {qr_file}")
                print(f"Show QR to scanner within {config.TEMP_QR_LIFETIME_SECONDS} seconds")
            else:
                print(f"Failed: {qr_file}")
        elif choice == "2":
            break
        else:
            print("Invalid option")


def management_interface(system):
    while True:
        print("\n=== MANAGEMENT ===")
        print("1. Add user")
        print("2. Remove user")
        print("3. List active users")
        print("4. View access log")
        print("5. System status")
        print("6. Test door lock")
        print("7. Back to main menu")
        choice = input("Choose option (1-7): ").strip()

        if choice == "1":
            _add_user_flow(system)
        elif choice == "2":
            _remove_user_flow(system)
        elif choice == "3":
            _list_users(system)
        elif choice == "4":
            _view_access_log(system)
        elif choice == "5":
            _show_status(system)
        elif choice == "6":
            system.door_lock.unlock()
        elif choice == "7":
            break
        else:
            print("Invalid option")


def _add_user_flow(system):
    user_id = input("User ID: ").strip()
    zone = input("Zone / room / lab (e.g. 'lab-1'): ").strip()

    default_checkin = datetime.now().replace(hour=9, minute=0, second=0, microsecond=0)
    default_checkout = (default_checkin + timedelta(days=1)).replace(hour=18, minute=0)

    checkin_str = input(
        f"Start (YYYY-MM-DD HH:MM) [{default_checkin.strftime('%Y-%m-%d %H:%M')}]: "
    ).strip()
    checkin_str = _parse_or_default(checkin_str, default_checkin)
    if checkin_str is None:
        return

    checkout_str = input(
        f"End (YYYY-MM-DD HH:MM) [{default_checkout.strftime('%Y-%m-%d %H:%M')}]: "
    ).strip()
    checkout_str = _parse_or_default(checkout_str, default_checkout)
    if checkout_str is None:
        return

    system.add_user(user_id, zone, checkin_str, checkout_str)


def _parse_or_default(raw, default_dt):
    if not raw:
        return default_dt.isoformat()
    try:
        return datetime.strptime(raw, "%Y-%m-%d %H:%M").isoformat()
    except ValueError:
        print("Invalid date format")
        return None


def _remove_user_flow(system):
    user_id = input("User ID to remove: ").strip()
    if not user_id:
        print("User ID required")
        return
    confirm = input(f"Revoke access for '{user_id}'? (y/n): ").strip().lower()
    if confirm == "y":
        system.remove_user(user_id)
    else:
        print("Cancelled")


def _list_users(system):
    users = system.get_active_users_list()
    if not users:
        print("No active users")
        return

    print("\nACTIVE USERS:")
    print("-" * 70)
    print(f"{'User ID':<15} {'Zone':<12} {'PIN':<8} {'Start':<20} {'End':<20}")
    print("-" * 70)
    for u in users:
        print(
            f"{u['user_id']:<15} {u['zone']:<12} {u['pin']:<8} "
            f"{str(u['check_in']):<20} {str(u['check_out']):<20}"
        )


def _view_access_log(system):
    events = system.get_recent_access_events()
    if not events:
        print("No access events recorded")
        return

    print("\nRECENT ACCESS EVENTS:")
    print("-" * 70)
    for e in events:
        status = "GRANTED" if e["success"] == "True" else "DENIED"
        print(f"{e['time']}  {status:<8} {e['user_id']:<12} {e['zone']:<10} {e['message']}")


def _show_status(system):
    print("\n=== SYSTEM STATUS ===")
    print(f"Camera available: {system.camera_available}")
    print(f"Active QR codes: {system.qr_manager.get_active_count()}")
    print(f"QR lifetime: {config.TEMP_QR_LIFETIME_SECONDS}s")
    print(f"Locked accounts: {system.authenticator.locked_account_count()}")
    print(f"MQTT connected: {system.mqtt_handler.connected}")


def main_menu(system):
    while True:
        print("\n=== ACCESS CONTROL SYSTEM ===")
        print("1. Start camera scanner")
        print("2. Access (generate QR)")
        print("3. Management (users, log, status)")
        print("4. Exit")
        choice = input("Choose option (1-4): ").strip()

        if choice == "1":
            system.start_scanner()
        elif choice == "2":
            access_interface(system)
        elif choice == "3":
            management_interface(system)
        elif choice == "4":
            break
        else:
            print("Invalid option")
