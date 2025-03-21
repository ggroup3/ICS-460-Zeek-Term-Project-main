
<!-- PROJECT LOGO -->
<br />
<div align="center">
  <a href="https://github.com/AJSommerness/ICS-460-Zeek-Term-Project.git">
    

<h3 align="center">Zeek Analysis GUI</h3>

  <p align="center">
    This project presents a real-time network traffic analysis tool using Zeek to extract data, paired with a custom Python GUI for effective monitoring and management of network logs.
  </p>
</div>





<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#contact">Contact</a></li>
    <li><a href="#key contributors">Key Contributors</a></li>
  </ol>
</details>



<!-- ABOUT THE PROJECT -->
## About The Project

This project develops a real-time network log file analyzer designed to process and visualize network traffic data effectively. Utilizing Zeek for robust data extraction, our system is paired with a custom Python GUI application to analyze and manage the data collected. The GUI�s functionalities entail:

- **File Selection**: Users can choose specific log directories and files for analysis through a file dialog interface.
- **Live Traffic Monitoring**: The system can analyze network logs in real-time to provide up-to-date information about network activity.
- **Data Filtering**: Logs can be filtered by protocols to focus on specific types of network traffic.
- **Summary and Analysis Display**: The application displays a summary of the network traffic, including the number of connections, most common protocols, and top network talkers. It also identifies and highlights suspicious activities, such as failed connection attempts.
- **Graphical Visualization**: Protocol distribution is visually represented through bar graphs, aiding in the quick assessment of network traffic status.

With these features, our program offers a powerful tool for network administrators and cybersecurity professionals to enhance their monitoring capabilities and improve network security measures.

<p align="right">(<a href="#readme-top">back to top</a>)</p>




### Built With

* [![Python][Python.org]][Python-url]
* [![Zeek][Zeek.org]][Zeek-url]


<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- GETTING STARTED -->
## Getting Started

To get a local copy up and running follow these simple example steps.

### Prerequisites

This project requires Python and Zeek. Here's how to install them:
* python3.8
  ```sh
  sudo apt-get install python3.8
  ```
Installation instruction for Zeek can be found on the [official Zeek Documentation](https://docs.zeek.org/en/master/)
Additionally, for a visual guide, watch this [Instalation video on YouTube](https://www.youtube.com/watch?v=4b_dW5JdE5U&t=1992s)
* Zeek
 ```sh
  sudo apt-get install zeek
 ```
  
### Installing VirtualBox and Ubuntu

1. **Download and Install VirtualBox**:
   - Visit the [VirtualBox downloads page](https://www.virtualbox.org/wiki/Downloads) and download the version suitable for your operating system.
   - Install VirtualBox by following the instructions specific to your OS.

2. **Download Ubuntu ISO**:
   - Download the Ubuntu ISO file from the [official Ubuntu website](https://ubuntu.com/download/desktop).

3. **Creating a Virtual Machine (VM)**:
   - Open VirtualBox and click on "New" to create a new virtual machine.
   - Name your VM, select "Linux" as the type, and choose "Ubuntu (64-bit)" as the version.
   - Allocate memory (RAM) to your VM; a minimum of 2048 MB is recommended.
   - Follow the prompts to create a virtual hard disk and allocate space for it.

4. **Installing Ubuntu in VirtualBox**:
   - Start your newly created VM and point it to the Ubuntu ISO file when prompted.
   - Follow the installation instructions on the screen to install Ubuntu.

5. **Install Zeek on Ubuntu**:
   - Once Ubuntu is installed, you can follow the Zeek installation steps provided in the prerequisites section above.
### Installation of Repository
1. Clone the repo
   ```sh
   git clone https://github.com/AJSommerness/ICS-460-Zeek-Term-Project.git
   ```
2. Install required Python Packages
   ```sh
   pip install -r requirements.txt
   ```

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- USAGE EXAMPLES -->
## Usage

possible vidoe of running code if i have time.


<p align="right">(<a href="#readme-top">back to top</a>)</p>







<!-- CONTRIBUTING -->
## Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

If you have a suggestion that would make this better, please fork the repo and create a pull request. You can also simply open an issue with the tag "enhancement".
Don't forget to give the project a star! Thanks again!

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

<p align="right">(<a href="#readme-top">back to top</a>)</p>





<!-- CONTACT -->
## Contact

Project Link: [https://github.com/github_username/repo_name](https://github.com/github_username/repo_name)

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- Key Contributors -->
## Key Contributors

* [Mohamud Yusuf](https://github.com/ggroup3)
* [Aidan Sommerness](https://github.com/AJSommerness)


<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[Python.org]: https://www.python.org/static/community_logos/python-logo.png "Python"
[Python-url]: https://www.python.org
[Zeek.org]: https://www.zeek.org/logo-zeek.svg "Zeek"
[Zeek-url]: https://www.zeek.org



#
