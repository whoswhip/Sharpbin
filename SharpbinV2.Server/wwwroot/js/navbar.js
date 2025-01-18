function AddToDom() {
    var nav = document.createElement("nav");
    nav.innerHTML = "<a href='index.html'>Home</a> | <a href='about.html'>About</a> | <a href='contact.html'>Contact</a>";
    document.body.appendChild(nav);
    console.log("Added nav to dom");
}
document.addEventListener("DOMContentLoaded", function () {
    AddToDom();
});