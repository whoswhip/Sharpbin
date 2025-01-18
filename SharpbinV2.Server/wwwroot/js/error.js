const errors = {
    "400": "You've made a bad request.",
    "401": "You are unauthorized to access this page.",
    "403": "Forbidden! You don't have permission.",
    "404": "Page not found.",
    "500": "Internal server error.",
};

document.addEventListener("DOMContentLoaded", function () {
    var queries = new URLSearchParams(window.location.search);
    var error = queries.get("error");
    var message = queries.get("message");
    var errorElement = document.getElementById("error-header");
    var messageElement = document.getElementById("error-message");

    if (error != null) {
        errorElement.innerText = errors[error];
    }
    if (message != null) {
        messageElement.innerText = message;
    }
});