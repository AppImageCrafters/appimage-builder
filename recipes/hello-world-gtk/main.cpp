#include <gtk/gtk.h>

// callback function which is called when button is clicked
static void on_button_clicked(GtkButton *btn, gpointer data) {
    // change button label when it's clicked
    gtk_button_set_label(btn, "Hello World");
}

// callback function which is called when application is first started
static void on_app_activate(GApplication *app, gpointer data) {
    // create a new application window for the application
    // GtkApplication is sub-class of GApplication
    // downcast GApplication* to GtkApplication* with GTK_APPLICATION() macro
    GtkWidget *window = gtk_application_window_new(GTK_APPLICATION(app));
    // a simple push button
    GtkWidget *btn = gtk_button_new_with_label("Click Me!");
    // connect the event-handler for "clicked" signal of button
    g_signal_connect(btn, "clicked", G_CALLBACK(on_button_clicked), NULL);
    // add the button to the window
    gtk_container_add(GTK_CONTAINER(window), btn);
    // display the window
    gtk_widget_show_all(GTK_WIDGET(window));
}

int main(int argc, char *argv[]) {
    // create new GtkApplication with an unique application ID
    GtkApplication *app = gtk_application_new(
        "org.gtkmm.example.HelloApp",
        G_APPLICATION_FLAGS_NONE
    );
    // connect the event-handler for "activate" signal of GApplication
    // G_CALLBACK() macro is used to cast the callback function pointer
    // to generic void pointer
    g_signal_connect(app, "activate", G_CALLBACK(on_app_activate), NULL);
    // start the application, terminate by closing the window
    // GtkApplication* is upcast to GApplication* with G_APPLICATION() macro
    int status = g_application_run(G_APPLICATION(app), argc, argv);
    // deallocate the application object
    g_object_unref(app);
    return status;
}