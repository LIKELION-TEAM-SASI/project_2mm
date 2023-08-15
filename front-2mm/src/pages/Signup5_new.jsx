import React, { useEffect, useState } from "react";
import styled from "styled-components";
import { useLocation, useNavigate } from "react-router-dom";
import axios from "axios";

const Container = styled.div`
  position: relative;
  margin: 30px 0;
  max-width: 375px;
  height: 740px;
  background: white;
  border: 1px solid gray;
  margin: 30px auto;

  @media screen and (max-width: 768px) {
    width: 100%;
    padding-left: 0rem;
    padding-right: 0rem;
  }
`;

const Back = styled.button`
  position: relative;
  margin-top: 17px;
  margin-left: 15px;
  background: transparent;
  border: none;
  cursor: pointer;
`;

const SubTitle = styled.div`
  position: relative;
  top: 25px;
  left: 25px;
`;

const Whitebox = styled.div`
  position: relative;
  top: 50px;
  left: 5px;
`;

const ImageUpload = styled.div`
  position: relative;
  width: 320px;
  height: 242px;
  bottom: 345px;
  left: 25px;
  flex-shrink: 0;
  border-radius: 16px;
  background: pink;
`;

const GroupName = styled.div`
  position: relative;
  width: 270px;
  height: 22px;
  left: 41px;
  top: -330px;

  font-family: "Inter";
  font-style: normal;
  font-weight: 700;
  font-size: 20px;
  line-height: 22px;
  color: #181818;
`;
const GroupInfo = styled.div`
  position: relative;
  width: 127px;
  height: 22px;
  left: 41px;
  top: -323px;

  font-family: "Inter";
  font-style: normal;
  font-weight: 300;
  font-size: 16px;
  line-height: 22px;
  color: #181818;
`;

const NextBtn = styled.button`
  position: relative;
  bottom: 90px;
  left: 22px;
  background: transparent;
  border: none;
  cursor: pointer;
`;

const Signup5_new = () => {
  const [group, setGroup] = useState(null);

  useEffect(() => {
    const code = localStorage.getItem("code");

    const fetchData = async () => {
      try {
        // API 호출
        const response = await axios.get(
          `http://127.0.0.1:8000/group/${code}/`
        );
        setGroup(response.data);
      } catch (error) {
        console.error("Error fetching data:", error);
      }
    };
    fetchData(); // fetchData 함수 호출 (데이터를 서버에서 가져옴)
  }, []);

  const navigate = useNavigate();
  const handleClick = () => {
    navigate("/Home");
  };

  return (
    <Container>
      <Back>
        <img src={`${process.env.PUBLIC_URL}/images/backbtn.svg`} alt="Back" />
      </Back>
      <SubTitle>
        <img
          src={`${process.env.PUBLIC_URL}/images/subtitle_group.svg`}
          alt="SubTitle"
        />
      </SubTitle>
      <Whitebox>
        <img
          src={`${process.env.PUBLIC_URL}/images/whitebox.svg`}
          alt="WhiteBox"
        />
        <ImageUpload>
          {group && group.profile ? (
            <img
              style={{ width: "320px", height: "242px", objectFit: "cover" }}
              src={`http://127.0.0.1:8000${group.profile}`}
            />
          ) : null}
        </ImageUpload>
        {group ? <GroupName>{group.name}</GroupName> : null}
        {group ? <GroupInfo>{group.info}</GroupInfo> : null}
      </Whitebox>
      <NextBtn onClick={handleClick}>
        <img src={`${process.env.PUBLIC_URL}/images/startbtn.svg`} alt="Next" />
      </NextBtn>
    </Container>
  );
};

export default Signup5_new;
