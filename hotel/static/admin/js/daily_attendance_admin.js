(function (djangoJQuery) {
    djangoJQuery(document).ready(function () {
        // Function to update students based on the selected hostel
        function updateStudents() {
            var selectedHostelId = djangoJQuery('#id_hostel').val();
            var studentsSelect = djangoJQuery('#id_students');

            // Clear previous options
            studentsSelect.find('option').remove();

            // Make AJAX request to get students for the selected hostel
            djangoJQuery.ajax({
                url: '/get_students/',
                data: {hostel_id: selectedHostelId},
                dataType: 'json',
                success: function (data) {
                    // Add new options based on the response
                    djangoJQuery.each(data.students, function (index, student) {
                        studentsSelect.append(djangoJQuery('<option></option>').attr('value', student.id).text(student.text));
                    });
                },
                error: function (xhr, status, error) {
                    console.error('Error fetching students:', error);
                }
            });
        }

        // Bind the function to the change event of the hostel select field
        djangoJQuery('#id_hostel').on('change', updateStudents);

        // Initial call to populate students based on the default value of hostel
        updateStudents();
    });
})(django.jQuery);
