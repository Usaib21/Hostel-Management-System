// static/admin/js/take_attendance_admin.js

(function ($) {
    $(document).ready(function () {
        function updateStudents() {
            var selectedHostelId = $('#id_hostel').val();
            var studentsSelect = $('#id_students');

            // Clear previous options
            studentsSelect.find('option').remove();

            // Make AJAX request to get students for the selected hostel
            $.getJSON('/get_students/', {hostel_id: selectedHostelId}, function (data) {
                // Add new options based on the response
                $.each(data.students, function (index, student) {
                    studentsSelect.append($('<option></option>').attr('value', student.id).text(student.text));
                });
            });
        }

        // Bind the function to the change event of the hostel select field
        $('#id_hostel').on('change', updateStudents);

        // Initial call to populate students based on the default value of hostel
        updateStudents();
    });
})(django.jQuery);
