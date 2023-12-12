# room/management/commands/populate_rooms.py
from django.core.management.base import BaseCommand
from room.models import Hostel, HostelRoom

class Command(BaseCommand):
    help = 'Populates rooms for all hostels and floors'

    def handle(self, *args, **kwargs):
        # Delete all existing rooms before populating new ones
        HostelRoom.objects.all().delete()

        hostels = Hostel.objects.all()
        floors = range(1, 5)  # Assuming you have floors numbered from 1 to 4
        room_number = 1  # Start room numbering at 1 for each floor

        for hostel in hostels:
            for floor in floors:
                for _ in range(30):
                    if room_number < 10:
                        room_number_formatted = f'{floor}0{room_number}'
                    else:
                        room_number_formatted = f'{floor}{room_number}'
                    
                    room = HostelRoom(
                        hostel=hostel,
                        floor_number=floor,
                        room_number=room_number_formatted,
                        capacity=3,  # Set capacity as needed
                        is_phd_only=False,  # Set is_phd_only as needed
                    )
                    room.save()
                    room_number += 1  # Increment room number within the floor
                room_number = 1  # Reset room number for the next floor

        self.stdout.write(self.style.SUCCESS('Rooms populated successfully'))


# from django.core.management.base import BaseCommand
# from room.models import Hostel, HostelRoom

# class Command(BaseCommand):
#     help = 'Populate HostelRoom table with rooms'

#     def handle(self, *args, **options):
#         hostels = Hostel.objects.all()
#         for hostel in hostels:
#             for floor_number in range(1, 5):  # Floors 1 to 4
#                 for room_number in range(1, 31):  # Rooms 1 to 30 per floor
#                     room = HostelRoom(
#                         hostel=hostel,
#                         floor_number=floor_number,
#                         room_number=room_number,
#                     )
#                     room.save()

#         self.stdout.write(self.style.SUCCESS('Successfully populated rooms'))
