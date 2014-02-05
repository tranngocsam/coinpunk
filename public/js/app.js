jQuery.ajaxSetup({
  beforeSend: function(xhr) {
    var token = jQuery('meta[name="csrf-token"]').attr('content');
    xhr.setRequestHeader('X_CSRF_TOKEN', token);
  }
});