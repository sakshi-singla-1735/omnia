Prerequisites
=================

1. Choose a server outside of your intended cluster with the mentioned `storage requirements <RHELSpace.html>`_ to function as your Omnia Infrastructure Manager (OIM).

2. Ensure that the OIM has a full-featured RHEL operating system (OS) installed. For a complete list of supported RHEL OS versions, check out the `Support Matrix <../../Overview/SupportMatrix/OperatingSystems/index.html>`_.

3. Enable the **AppStream** and **BaseOS** repositories via the RHEL subscription manager.

4. Ensure that the OIM has internet access and Git installed. If Git is not installed, use the below commands to install it. ::

    dnf install git -y

.. note:: If the OIM server has an Infiniband NIC installed, run the below command to install the hardware drivers and Infiniband-related packages:
    ::
        yum groupinstall "Infiniband Support" -y

5. Clone the `Omnia artifacts repository <https://github.com/dell/omnia-artifactory/tree/omnia-container>`_ and then run the following command to build the container images. For detailed information, `click here <https://github.com/dell/omnia-artifactory/blob/omnia-container/README.md>`_. ::

    ./build_images.sh all
