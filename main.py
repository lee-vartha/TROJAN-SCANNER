from shredr_frontend import launch_gui
from database import init_db
from ttkthemes import ThemedTk

init_db()
if __name__ == "__main__":
    gui = launch_gui()
    gui.setup_window()
    gui.setup_styles()
    gui.create_widgets()
    gui.root.mainloop() # starts main loop
